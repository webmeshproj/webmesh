/*
Copyright 2023 Avi Zimmerman <avi.zimmerman@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package peers contains an interface for managing nodes in the mesh.
package peers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/dominikbraun/graph"
	"github.com/dominikbraun/graph/draw"
	"github.com/google/go-cmp/cmp"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	peergraph "github.com/webmeshproj/webmesh/pkg/meshdb/peers/graph"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// ErrNodeNotFound is returned when a node is not found.
var ErrNodeNotFound = errors.New("node not found")

// InvalidNodeIDChars are the characters that are not allowed in node IDs.
var InvalidNodeIDChars = []rune{'/', '\\', ':', '*', '?', '"', '\'', '<', '>', '|', ','}

// ReservedNodeIDs are reserved node IDs.
var ReservedNodeIDs = []string{"self", "local", "localhost", "leader", "voters", "observers"}

// IsValidID returns true if the given node ID is valid.
func IsValidID(id string) bool {
	if len(id) == 0 {
		return false
	}
	if slices.Contains(ReservedNodeIDs, id) {
		return false
	}
	for _, c := range InvalidNodeIDChars {
		if strings.ContainsRune(id, c) {
			return false
		}
	}
	return true
}

// EdgeAttrsForProto returns the edge attributes for the given protocol.
func EdgeAttrsForProto(proto v1.ConnectProtocol) map[string]string {
	attrs := map[string]string{}
	switch proto {
	case v1.ConnectProtocol_CONNECT_ICE:
		attrs[v1.EdgeAttribute_EDGE_ATTRIBUTE_ICE.String()] = "true"
	case v1.ConnectProtocol_CONNECT_LIBP2P:
		attrs[v1.EdgeAttribute_EDGE_ATTRIBUTE_LIBP2P.String()] = "true"
	default:
		attrs[v1.EdgeAttribute_EDGE_ATTRIBUTE_NATIVE.String()] = "true"
	}
	return attrs
}

// ProtoFromEdgeAttrs returns the protocol for the given edge attributes.
func ProtoFromEdgeAttrs(attrs map[string]string) v1.ConnectProtocol {
	if attrs == nil {
		return v1.ConnectProtocol_CONNECT_NATIVE
	}
	if _, ok := attrs[v1.EdgeAttribute_EDGE_ATTRIBUTE_ICE.String()]; ok {
		return v1.ConnectProtocol_CONNECT_ICE
	}
	if _, ok := attrs[v1.EdgeAttribute_EDGE_ATTRIBUTE_LIBP2P.String()]; ok {
		return v1.ConnectProtocol_CONNECT_LIBP2P
	}
	return v1.ConnectProtocol_CONNECT_NATIVE
}

// Peers is the peers interface.
type Peers interface {
	// Resolver returns a resolver backed by the storage
	// of this instance.
	Resolver() Resolver
	// Graph returns the graph of nodes.
	Graph() peergraph.Graph
	// Put creates or updates a node.
	Put(ctx context.Context, n *v1.MeshNode) error
	// Get gets a node by ID.
	Get(ctx context.Context, id string) (peergraph.MeshNode, error)
	// GetByPubKey gets a node by their public key.
	GetByPubKey(ctx context.Context, key crypto.PublicKey) (peergraph.MeshNode, error)
	// Delete deletes a node.
	Delete(ctx context.Context, id string) error
	// List lists all nodes.
	List(ctx context.Context) ([]peergraph.MeshNode, error)
	// ListIDs lists all node IDs.
	ListIDs(ctx context.Context) ([]string, error)
	// ListPublicNodes lists all public nodes.
	ListPublicNodes(ctx context.Context) ([]peergraph.MeshNode, error)
	// ListByZoneID lists all nodes in a zone.
	ListByZoneID(ctx context.Context, zoneID string) ([]peergraph.MeshNode, error)
	// ListByFeature lists all nodes with a given feature.
	ListByFeature(ctx context.Context, feature v1.Feature) ([]peergraph.MeshNode, error)
	// AddEdge adds an edge between two nodes.
	PutEdge(ctx context.Context, edge *v1.MeshEdge) error
	// RemoveEdge removes an edge between two nodes.
	RemoveEdge(ctx context.Context, from, to string) error
	// DrawGraph draws the graph of nodes to the given Writer.
	DrawGraph(ctx context.Context, w io.Writer) error
}

// New returns a new Peers interface.
func New(db storage.MeshStorage) Peers {
	return &peerDB{
		db:    db,
		graph: peergraph.NewGraph(db),
	}
}

type peerDB struct {
	db    storage.MeshStorage
	graph peergraph.Graph
}

func (p *peerDB) Resolver() Resolver {
	return &peerResolver{p.db}
}

func (p *peerDB) Graph() peergraph.Graph { return p.graph }

func (p *peerDB) Put(ctx context.Context, node *v1.MeshNode) error {
	// Dedup the wireguard endpoints.
	seen := make(map[string]struct{})
	var wgendpoints []string
	for _, endpoint := range node.GetWireguardEndpoints() {
		if _, ok := seen[endpoint]; ok {
			continue
		}
		seen[endpoint] = struct{}{}
		wgendpoints = append(wgendpoints, endpoint)
	}
	node.WireguardEndpoints = wgendpoints
	node.JoinedAt = timestamppb.New(time.Now().UTC())
	err := p.graph.AddVertex(peergraph.MeshNode{MeshNode: node})
	if err != nil {
		return fmt.Errorf("put node: %w", err)
	}
	return nil
}

func (p *peerDB) Get(ctx context.Context, id string) (peergraph.MeshNode, error) {
	node, err := p.graph.Vertex(id)
	if err != nil {
		if errors.Is(err, graph.ErrVertexNotFound) {
			return peergraph.MeshNode{}, ErrNodeNotFound
		}
		return peergraph.MeshNode{}, fmt.Errorf("get node: %w", err)
	}
	return node, nil
}

// GetByPubKey gets a node by their public key.
func (p *peerDB) GetByPubKey(ctx context.Context, key crypto.PublicKey) (peergraph.MeshNode, error) {
	nodes, err := p.List(ctx)
	if err != nil {
		return peergraph.MeshNode{}, fmt.Errorf("list nodes: %w", err)
	}
	for _, node := range nodes {
		if node.GetPublicKey() != "" {
			key, err := crypto.DecodePublicKey(node.GetPublicKey())
			if err != nil {
				return peergraph.MeshNode{}, fmt.Errorf("parse host public key: %w", err)
			}
			if key.Equals(key) {
				return node, nil
			}
		}
	}
	return peergraph.MeshNode{}, ErrNodeNotFound
}

func (p *peerDB) Delete(ctx context.Context, id string) error {
	edges, err := p.graph.Edges()
	if err != nil {
		return fmt.Errorf("get edges: %w", err)
	}
	for _, edge := range edges {
		if edge.Source == id || edge.Target == id {
			err = p.graph.RemoveEdge(edge.Source, edge.Target)
			if err != nil {
				return fmt.Errorf("remove edge: %w", err)
			}
		}
	}
	err = p.graph.RemoveVertex(id)
	if err != nil {
		if errors.Is(err, graph.ErrVertexNotFound) {
			// We don't return this error in the graph store
			// implementation, so we don't return it here either.
			return nil
		}
		return fmt.Errorf("remove vertex: %w", err)
	}
	return nil
}

func (p *peerDB) List(ctx context.Context) ([]peergraph.MeshNode, error) {
	out := make([]peergraph.MeshNode, 0)
	err := p.db.IterPrefix(ctx, peergraph.NodesPrefix.String(), func(key, value string) error {
		if key == peergraph.NodesPrefix.String() {
			return nil
		}
		var node peergraph.MeshNode
		err := node.Unmarshal([]byte(value))
		if err != nil {
			return fmt.Errorf("unmarshal node: %w", err)
		}
		out = append(out, node)
		return nil
	})
	return out, err
}

func (p *peerDB) ListIDs(ctx context.Context) ([]string, error) {
	keys, err := p.db.List(ctx, peergraph.NodesPrefix.String())
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	ids := make([]string, 0)
	for _, key := range keys {
		ids = append(ids, strings.TrimPrefix(key, peergraph.NodesPrefix.String()+"/"))
	}
	return ids, nil
}

func (p *peerDB) ListPublicNodes(ctx context.Context) ([]peergraph.MeshNode, error) {
	nodes, err := p.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	out := make([]peergraph.MeshNode, 0)
	for _, node := range nodes {
		n := node
		if n.PrimaryEndpoint != "" {
			out = append(out, n)
		}
	}
	return out, nil
}

func (p *peerDB) ListByZoneID(ctx context.Context, zoneID string) ([]peergraph.MeshNode, error) {
	nodes, err := p.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	out := make([]peergraph.MeshNode, 0)
	for _, node := range nodes {
		n := node
		if n.GetZoneAwarenessId() == zoneID {
			out = append(out, n)
		}
	}
	return out, nil
}

func (p *peerDB) ListByFeature(ctx context.Context, feature v1.Feature) ([]peergraph.MeshNode, error) {
	nodes, err := p.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	out := make([]peergraph.MeshNode, 0)
	for _, node := range nodes {
		n := node
		if n.HasFeature(feature) {
			out = append(out, n)
		}
	}
	return out, nil
}

func (p *peerDB) PutEdge(ctx context.Context, edge *v1.MeshEdge) error {
	if edge.Source == edge.Target {
		return nil
	}
	opts := []func(*graph.EdgeProperties){graph.EdgeWeight(int(edge.Weight))}
	if len(edge.Attributes) > 0 {
		for k, v := range edge.Attributes {
			opts = append(opts, graph.EdgeAttribute(k, v))
		}
	}
	// Save the raft log some trouble by checking if the edge already exists.
	graphEdge, err := p.graph.Edge(edge.Source, edge.Target)
	if err == nil {
		// Check if the weight or attributes changed
		if !cmp.Equal(graphEdge.Properties.Attributes, edge.Attributes) {
			return p.graph.UpdateEdge(edge.Source, edge.Target, opts...)
		}
		if graphEdge.Properties.Weight != int(edge.Weight) {
			return p.graph.UpdateEdge(edge.Source, edge.Target, opts...)
		}
		return nil
	}
	if !errors.Is(err, graph.ErrEdgeNotFound) {
		return fmt.Errorf("get edge: %w", err)
	}
	err = p.graph.AddEdge(edge.Source, edge.Target, opts...)
	if err != nil && !errors.Is(err, graph.ErrEdgeAlreadyExists) {
		return fmt.Errorf("add edge: %w", err)
	}
	return nil
}

func (p *peerDB) RemoveEdge(ctx context.Context, from, to string) error {
	err := p.graph.RemoveEdge(from, to)
	if err != nil {
		if err == graph.ErrEdgeNotFound {
			return nil
		}
		return fmt.Errorf("remove edge: %w", err)
	}
	return nil
}

func (p *peerDB) DrawGraph(ctx context.Context, w io.Writer) error {
	graph := graph.Graph[string, peergraph.MeshNode](p.graph)
	err := draw.DOT(graph, w)
	if err != nil {
		return fmt.Errorf("draw graph: %w", err)
	}
	return nil
}
