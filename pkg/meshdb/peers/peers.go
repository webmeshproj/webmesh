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
	"time"

	"github.com/dominikbraun/graph"
	"github.com/dominikbraun/graph/draw"
	"github.com/google/go-cmp/cmp"
	v1 "github.com/webmeshproj/api/v1"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/types/known/timestamppb"

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
	Put(ctx context.Context, opts *PutOptions) (Node, error)
	// PutLease creates or updates a node lease.
	PutLease(ctx context.Context, opts *PutLeaseOptions) error
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
	// AddEdge adds an edge between two nodes.
	PutEdge(ctx context.Context, edge Edge) error
	// RemoveEdge removes an edge between two nodes.
	RemoveEdge(ctx context.Context, from, to string) error
	// DrawGraph draws the graph of nodes to the given Writer.
	DrawGraph(ctx context.Context, w io.Writer) error
}

// Node represents a node. Not all fields are populated in all contexts.
// A fully populated node is returned by Get and List.
type Node struct {
	// ID is the node's ID.
	ID string `json:"id"`
	// PublicKey is the node's public key.
	PublicKey wgtypes.Key `json:"publicKey"`
	// PrimaryEndpoint is the primary public endpoint of the node.
	PrimaryEndpoint string `json:"primaryEndpoint"`
	// WireGuardEndpoints are the available wireguard endpoints of the node.
	WireGuardEndpoints []string `json:"wireGuardEndpoints"`
	// ZoneAwarenessID is the node's zone awareness ID.
	ZoneAwarenessID string `json:"zoneAwarenessId"`
	// PrivateIPv4 is the node's private IPv4 address.
	PrivateIPv4 netip.Prefix `json:"privateIpv4"`
	// PrivateIPv6 is the node's IPv6 network.
	PrivateIPv6 netip.Prefix `json:"privateIpv6"`
	// GRPCPort is the node's GRPC port.
	GRPCPort int `json:"grpcPort"`
	// RaftPort is the node's Raft port.
	RaftPort int `json:"raftPort"`
	// CreatedAt is the time the node was created.
	CreatedAt time.Time `json:"createdAt"`
	// UpdatedAt is the time the node was last updated.
	UpdatedAt time.Time `json:"updatedAt"`
}

// MarshalJSON marshals a Node to JSON.
func (n Node) MarshalJSON() ([]byte, error) {
	type Alias Node
	return json.Marshal(&struct {
		PublicKey   string `json:"publicKey"`
		PrivateIPv4 string `json:"privateIpv4"`
		PrivateIPv6 string `json:"privateIpv6"`
		Alias
	}{
		PublicKey: n.PublicKey.String(),
		PrivateIPv4: func() string {
			if n.PrivateIPv4.IsValid() {
				return n.PrivateIPv4.String()
			}
			return ""
		}(),
		PrivateIPv6: func() string {
			if n.PrivateIPv6.IsValid() {
				return n.PrivateIPv6.String()
			}
			return ""
		}(),
		Alias: (Alias)(n),
	})
}

// UnmarshalJSON unmarshals a Node from JSON.
func (n *Node) UnmarshalJSON(b []byte) error {
	type Alias Node
	aux := &struct {
		PublicKey   string `json:"publicKey"`
		PrivateIPv4 string `json:"privateIpv4"`
		PrivateIPv6 string `json:"privateIpv6"`
		*Alias
	}{
		Alias: (*Alias)(n),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if aux.PublicKey != "" {
		key, err := wgtypes.ParseKey(aux.PublicKey)
		if err != nil {
			return fmt.Errorf("parse node public key: %w", err)
		}
		n.PublicKey = key
	}
	if aux.PrivateIPv4 != "" {
		network, err := netip.ParsePrefix(aux.PrivateIPv4)
		if err != nil {
			return fmt.Errorf("parse node private IPv4: %w", err)
		}
		n.PrivateIPv4 = network
	}
	if aux.PrivateIPv6 != "" {
		network, err := netip.ParsePrefix(aux.PrivateIPv6)
		if err != nil {
			return fmt.Errorf("parse node private IPv6: %w", err)
		}
		n.PrivateIPv6 = network
	}
	return nil
}

// Proto converts a Node to the protobuf representation.
func (n *Node) Proto(status v1.ClusterStatus) *v1.MeshNode {
	return &v1.MeshNode{
		Id:                 n.ID,
		PrimaryEndpoint:    n.PrimaryEndpoint,
		WireguardEndpoints: n.WireGuardEndpoints,
		ZoneAwarenessId:    n.ZoneAwarenessID,
		RaftPort:           int32(n.RaftPort),
		GrpcPort:           int32(n.GRPCPort),
		PublicKey: func() string {
			if len(n.PublicKey) > 0 {
				return n.PublicKey.String()
			}
			return ""
		}(),
		PrivateIpv4: func() string {
			if n.PrivateIPv4.IsValid() {
				return n.PrivateIPv4.String()
			}
			return ""
		}(),
		PrivateIpv6: func() string {
			if n.PrivateIPv6.IsValid() {
				return n.PrivateIPv6.String()
			}
			return ""
		}(),
		UpdatedAt:     timestamppb.New(n.UpdatedAt),
		CreatedAt:     timestamppb.New(n.CreatedAt),
		ClusterStatus: status,
	}
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

func (p *peers) Put(ctx context.Context, opts *PutOptions) (Node, error) {
	// Dedup the wireguard endpoints.
	seen := make(map[string]struct{})
	var wgendpoints []string
	for _, endpoint := range opts.WireGuardEndpoints {
		if _, ok := seen[endpoint]; ok {
			continue
		}
		seen[endpoint] = struct{}{}
		wgendpoints = append(wgendpoints, endpoint)
	}
	// Get any existing node.
	node, err := p.graph.Vertex(opts.ID)
	if err != nil && !errors.Is(err, graph.ErrVertexNotFound) {
		return Node{}, fmt.Errorf("get node: %w", err)
	}
	// Fill in the missing fields.
	node.ID = opts.ID
	node.PublicKey = opts.PublicKey
	node.PrimaryEndpoint = opts.PrimaryEndpoint
	node.WireGuardEndpoints = wgendpoints
	node.ZoneAwarenessID = opts.ZoneAwarenessID
	node.GRPCPort = opts.GRPCPort
	node.RaftPort = opts.RaftPort
	node.UpdatedAt = time.Now().UTC()
	// If the node doesn't exist, set the creation timestamp.
	if errors.Is(err, graph.ErrVertexNotFound) {
		node.CreatedAt = node.UpdatedAt
	}
	err = p.graph.AddVertex(node)
	if err != nil {
		return Node{}, fmt.Errorf("add vertex: %w", err)
	}
	// Return the full node.
	out, err := p.graph.Vertex(opts.ID)
	if err != nil {
		return Node{}, fmt.Errorf("get vertex: %w", err)
	}
	return out, nil
}

func (p *peers) PutLease(ctx context.Context, opts *PutLeaseOptions) error {
	if !opts.IPv4.IsValid() && !opts.IPv6.IsValid() {
		return errors.New("at least one of IPv4 or IPv6 must be set")
	}
	node, err := p.graph.Vertex(opts.ID)
	if err != nil {
		return fmt.Errorf("get node: %w", err)
	}
	if opts.IPv4.IsValid() {
		node.PrivateIPv4 = opts.IPv4
	}
	if opts.IPv6.IsValid() {
		node.PrivateIPv6 = opts.IPv6
	}
	err = p.graph.AddVertex(node)
	if err != nil {
		return fmt.Errorf("add vertex: %w", err)
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
	err := p.db.IterPrefix(ctx, NodesPrefix, func(key, value string) error {
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

// ListPublicNodes lists all public nodes.
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

// ListByZoneID lists all nodes in a zone.
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

// ListIDs returns a list of node IDs.
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

// PutEdge adds or updates an edge between two nodes.
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

// RemoveEdge removes an edge between two nodes.
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
