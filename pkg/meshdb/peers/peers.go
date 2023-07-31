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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/dominikbraun/graph"
	"github.com/dominikbraun/graph/draw"
	"github.com/google/go-cmp/cmp"
	v1 "github.com/webmeshproj/api/v1"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/webmeshproj/webmesh/pkg/storage"
)

// ErrNodeNotFound is returned when a node is not found.
var ErrNodeNotFound = errors.New("node not found")

// ErrEdgeNotFound is returned when an edge is not found.
var ErrEdgeNotFound = graph.ErrEdgeNotFound

// Graph is the graph.Graph implementation for the mesh network.
type Graph graph.Graph[string, Node]

// graphHasher is the hash key function for the graph.
func graphHasher(n Node) string { return n.ID }

// InvalidNodeIDChars are the characters that are not allowed in node IDs.
var InvalidNodeIDChars = []rune{'/', '\\', ':', '*', '?', '"', '\'', '<', '>', '|', ','}

// IsValidID returns true if the given node ID is valid.
func IsValidID(id string) bool {
	if len(id) == 0 {
		return false
	}
	for _, c := range InvalidNodeIDChars {
		if strings.ContainsRune(id, c) {
			return false
		}
	}
	return true
}

// Peers is the peers interface.
type Peers interface {
	// Graph returns the graph of nodes.
	Graph() Graph
	// Put creates or updates a node.
	Put(ctx context.Context, n Node) error
	// Get gets a node by ID.
	Get(ctx context.Context, id string) (Node, error)
	// Delete deletes a node.
	Delete(ctx context.Context, id string) error
	// List lists all nodes.
	List(ctx context.Context) ([]Node, error)
	// ListIDs lists all node IDs.
	ListIDs(ctx context.Context) ([]string, error)
	// ListPublicNodes lists all public nodes.
	ListPublicNodes(ctx context.Context) ([]Node, error)
	// ListByZoneID lists all nodes in a zone.
	ListByZoneID(ctx context.Context, zoneID string) ([]Node, error)
	// ListByFeature lists all nodes with a given feature.
	ListByFeature(ctx context.Context, feature v1.Feature) ([]Node, error)
	// AddEdge adds an edge between two nodes.
	PutEdge(ctx context.Context, edge Edge) error
	// RemoveEdge removes an edge between two nodes.
	RemoveEdge(ctx context.Context, from, to string) error
	// DrawGraph draws the graph of nodes to the given Writer.
	DrawGraph(ctx context.Context, w io.Writer) error
}

// Edge represents an edge between two nodes.
type Edge struct {
	// From is the ID of the source node.
	From string `json:"from"`
	// To is the ID of the target node.
	To string `json:"to"`
	// Weight is the weight of the edge.
	Weight int `json:"weight"`
	// Attrs are the edge's attributes.
	Attrs map[string]string `json:"attrs"`
}

// PutOptions are options for creating or updating a node.
type PutOptions struct {
	// ID is the node's ID.
	ID string
	// PublicKey is the node's public key.
	PublicKey wgtypes.Key
	// PrimaryEndpoint is the primary public endpoint of the node.
	PrimaryEndpoint string
	// WireGuardEndpoints are the available wireguard endpoints of the node.
	WireGuardEndpoints []string
	// ZoneAwarenessID is the node's zone awareness ID.
	ZoneAwarenessID string
	// GRPCPort is the node's GRPC port.
	GRPCPort int
	// RaftPort is the node's Raft port.
	RaftPort int
	// DNSPort is the node's DNS port.
	DNSPort int
	// Features are the node's features.
	Features []v1.Feature
}

// PutLeaseOptions are options for creating or updating a node lease.
type PutLeaseOptions struct {
	// ID is the node's ID.
	ID string
	// IPv4 is the node's IPv4 address.
	IPv4 netip.Prefix
	// IPv6 is the node's IPv6 network.
	IPv6 netip.Prefix
}

// New returns a new Peers interface.
func New(db storage.Storage) Peers {
	return &peers{
		db:    db,
		graph: NewGraph(db),
	}
}

type peers struct {
	db    storage.Storage
	graph Graph
}

func (p *peers) Graph() Graph { return p.graph }

func (p *peers) Put(ctx context.Context, node Node) error {
	// Dedup the wireguard endpoints.
	seen := make(map[string]struct{})
	var wgendpoints []string
	for _, endpoint := range node.WireGuardEndpoints {
		if _, ok := seen[endpoint]; ok {
			continue
		}
		seen[endpoint] = struct{}{}
		wgendpoints = append(wgendpoints, endpoint)
	}
	node.WireGuardEndpoints = wgendpoints
	err := p.graph.AddVertex(node)
	if err != nil {
		return fmt.Errorf("put node: %w", err)
	}
	return nil
}

func (p *peers) Get(ctx context.Context, id string) (Node, error) {
	node, err := p.graph.Vertex(id)
	if err != nil {
		if errors.Is(err, graph.ErrVertexNotFound) {
			return Node{}, ErrNodeNotFound
		}
		return Node{}, fmt.Errorf("get node: %w", err)
	}
	return node, nil
}

func (p *peers) Delete(ctx context.Context, id string) error {
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

func (p *peers) List(ctx context.Context) ([]Node, error) {
	out := make([]Node, 0)
	err := p.db.IterPrefix(ctx, NodesPrefix, func(_, value string) error {
		var node Node
		err := json.Unmarshal([]byte(value), &node)
		if err != nil {
			return fmt.Errorf("unmarshal node: %w", err)
		}
		out = append(out, node)
		return nil
	})
	return out, err
}

func (p *peers) ListIDs(ctx context.Context) ([]string, error) {
	keys, err := p.db.List(ctx, NodesPrefix)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	ids := make([]string, 0)
	for _, key := range keys {
		ids = append(ids, strings.TrimPrefix(key, NodesPrefix+"/"))
	}
	return ids, nil
}

func (p *peers) ListPublicNodes(ctx context.Context) ([]Node, error) {
	nodes, err := p.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	out := make([]Node, 0)
	for _, node := range nodes {
		if node.PrimaryEndpoint != "" {
			out = append(out, node)
		}
	}
	return out, nil
}

func (p *peers) ListByZoneID(ctx context.Context, zoneID string) ([]Node, error) {
	nodes, err := p.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	out := make([]Node, 0)
	for _, node := range nodes {
		if node.ZoneAwarenessID == zoneID {
			out = append(out, node)
		}
	}
	return out, nil
}

func (p *peers) ListByFeature(ctx context.Context, feature v1.Feature) ([]Node, error) {
	nodes, err := p.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	out := make([]Node, 0)
	for _, node := range nodes {
		if node.HasFeature(feature) {
			out = append(out, node)
		}
	}
	return out, nil
}

func (p *peers) PutEdge(ctx context.Context, edge Edge) error {
	if edge.From == edge.To {
		return nil
	}
	opts := []func(*graph.EdgeProperties){graph.EdgeWeight(edge.Weight)}
	if edge.Attrs != nil {
		for k, v := range edge.Attrs {
			opts = append(opts, graph.EdgeAttribute(k, v))
		}
	}
	// Save the raft log some trouble by checking if the edge already exists.
	graphEdge, err := p.graph.Edge(edge.From, edge.To)
	if err == nil {
		// Check if the weight or attributes changed
		if !cmp.Equal(graphEdge.Properties.Attributes, edge.Attrs) {
			return p.graph.UpdateEdge(edge.From, edge.To, opts...)
		}
		// Only update the weight if it's higher than the existing weight.
		if graphEdge.Properties.Weight != edge.Weight && edge.Weight > graphEdge.Properties.Weight {
			return p.graph.UpdateEdge(edge.From, edge.To, opts...)
		}
		return nil
	}
	if !errors.Is(err, graph.ErrEdgeNotFound) {
		return fmt.Errorf("get edge: %w", err)
	}
	err = p.graph.AddEdge(edge.From, edge.To, opts...)
	if err != nil && !errors.Is(err, graph.ErrEdgeAlreadyExists) {
		return fmt.Errorf("add edge: %w", err)
	}
	return nil
}

func (p *peers) RemoveEdge(ctx context.Context, from, to string) error {
	err := p.graph.RemoveEdge(from, to)
	if err != nil {
		if err == graph.ErrEdgeNotFound {
			return nil
		}
		return fmt.Errorf("remove edge: %w", err)
	}
	return nil
}

func (p *peers) DrawGraph(ctx context.Context, w io.Writer) error {
	graph := graph.Graph[string, Node](p.graph)
	err := draw.DOT(graph, w)
	if err != nil {
		return fmt.Errorf("draw graph: %w", err)
	}
	return nil
}
