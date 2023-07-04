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
	"database/sql"
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

	"github.com/webmeshproj/node/pkg/meshdb"
	"github.com/webmeshproj/node/pkg/meshdb/models"
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
	ID string
	// PublicKey is the node's public key.
	PublicKey wgtypes.Key
	// PrimaryEndpoint is the primary public endpoint of the node.
	PrimaryEndpoint string
	// WireGuardEndpoints are the available wireguard endpoints of the node.
	WireGuardEndpoints []string
	// ZoneAwarenessID is the node's zone awareness ID.
	ZoneAwarenessID string
	// PrivateIPv4 is the node's private IPv4 address.
	PrivateIPv4 netip.Prefix
	// PrivateIPv6 is the node's IPv6 network.
	PrivateIPv6 netip.Prefix
	// GRPCPort is the node's GRPC port.
	GRPCPort int
	// RaftPort is the node's Raft port.
	RaftPort int
	// CreatedAt is the time the node was created.
	CreatedAt time.Time
	// UpdatedAt is the time the node was last updated.
	UpdatedAt time.Time
}

// Proto converts a Node to the protobuf representation.
func (n Node) Proto(status v1.ClusterStatus) *v1.MeshNode {
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
	From string
	// To is the ID of the target node.
	To string
	// Weight is the weight of the edge.
	Weight int
	// Attrs are the edge's attributes.
	Attrs map[string]string
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
func New(db meshdb.DB) Peers {
	return &peers{
		db:    db,
		graph: NewGraph(db),
	}
}

type peers struct {
	db    meshdb.DB
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
	err := p.graph.AddVertex(Node{
		ID:                 opts.ID,
		PublicKey:          opts.PublicKey,
		PrimaryEndpoint:    opts.PrimaryEndpoint,
		WireGuardEndpoints: wgendpoints,
		ZoneAwarenessID:    opts.ZoneAwarenessID,
		GRPCPort:           opts.GRPCPort,
		RaftPort:           opts.RaftPort,
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
	})
	if err != nil {
		return Node{}, fmt.Errorf("add vertex: %w", err)
	}
	out, err := p.graph.Vertex(opts.ID)
	if err != nil {
		return Node{}, fmt.Errorf("get vertex: %w", err)
	}
	return out, nil
}

func (p *peers) PutLease(ctx context.Context, opts *PutLeaseOptions) error {
	q := models.New(p.db.Write())
	params := models.InsertNodeLeaseParams{
		NodeID:    opts.ID,
		CreatedAt: time.Now().UTC(),
	}
	if opts.IPv4.IsValid() {
		params.Ipv4 = sql.NullString{String: opts.IPv4.String(), Valid: true}
	}
	if opts.IPv6.IsValid() {
		params.Ipv6 = sql.NullString{String: opts.IPv6.String(), Valid: true}
	}
	_, err := q.InsertNodeLease(ctx, params)
	if err != nil {
		return fmt.Errorf("insert node lease: %w", err)
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
	if len(edges) > 0 {
		q := models.New(p.db.Write())
		err = q.DeleteNodeEdges(ctx, models.DeleteNodeEdgesParams{
			SrcNodeID: id,
			DstNodeID: id,
		})
		if err != nil {
			return fmt.Errorf("delete node edges: %w", err)
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
	q := models.New(p.db.Read())
	nodes, err := q.ListNodes(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []Node{}, nil
		}
		return nil, err
	}
	out := make([]Node, len(nodes))
	for i, node := range nodes {
		var key wgtypes.Key
		if node.PublicKey.Valid {
			key, err = wgtypes.ParseKey(node.PublicKey.String)
			if err != nil {
				return nil, fmt.Errorf("parse node public key: %w", err)
			}
		}
		var wireguardEndpoints []string
		if node.WireguardEndpoints.Valid {
			wireguardEndpoints = strings.Split(node.WireguardEndpoints.String, ",")
		}
		var networkv4, networkv6 netip.Prefix
		if node.PrivateAddressV4 != "" {
			networkv4, err = netip.ParsePrefix(node.PrivateAddressV4)
			if err != nil {
				return nil, fmt.Errorf("parse node network IPv4: %w", err)
			}
		}
		if node.PrivateAddressV6 != "" {
			networkv6, err = netip.ParsePrefix(node.PrivateAddressV6)
			if err != nil {
				return nil, fmt.Errorf("parse node network IPv6: %w", err)
			}
		}
		out[i] = Node{
			ID:                 node.ID,
			PublicKey:          key,
			PrimaryEndpoint:    node.PrimaryEndpoint.String,
			WireGuardEndpoints: wireguardEndpoints,
			ZoneAwarenessID:    node.ZoneAwarenessID.String,
			PrivateIPv4:        networkv4,
			PrivateIPv6:        networkv6,
			GRPCPort:           int(node.GrpcPort),
			RaftPort:           int(node.RaftPort),
			UpdatedAt:          node.UpdatedAt,
			CreatedAt:          node.CreatedAt,
		}
	}
	return out, nil
}

// ListPublicNodes lists all public nodes.
func (p *peers) ListPublicNodes(ctx context.Context) ([]Node, error) {
	q := models.New(p.db.Read())
	nodes, err := q.ListPublicNodes(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []Node{}, nil
		}
		return nil, err
	}
	out := make([]Node, len(nodes))
	for i, node := range nodes {
		var key wgtypes.Key
		if node.PublicKey.Valid {
			key, err = wgtypes.ParseKey(node.PublicKey.String)
			if err != nil {
				return nil, fmt.Errorf("parse node public key: %w", err)
			}
		}
		var wireguardEndpoints []string
		if node.WireguardEndpoints.Valid {
			wireguardEndpoints = strings.Split(node.WireguardEndpoints.String, ",")
		}
		var networkv4, networkv6 netip.Prefix
		if node.PrivateAddressV4 != "" {
			networkv4, err = netip.ParsePrefix(node.PrivateAddressV4)
			if err != nil {
				return nil, fmt.Errorf("parse node network IPv4: %w", err)
			}
		}
		if node.PrivateAddressV6 != "" {
			networkv6, err = netip.ParsePrefix(node.PrivateAddressV6)
			if err != nil {
				return nil, fmt.Errorf("parse node network IPv6: %w", err)
			}
		}
		out[i] = Node{
			ID:                 node.ID,
			PublicKey:          key,
			PrimaryEndpoint:    node.PrimaryEndpoint.String,
			WireGuardEndpoints: wireguardEndpoints,
			ZoneAwarenessID:    node.ZoneAwarenessID.String,
			PrivateIPv4:        networkv4,
			PrivateIPv6:        networkv6,
			GRPCPort:           int(node.GrpcPort),
			RaftPort:           int(node.RaftPort),
			UpdatedAt:          node.UpdatedAt,
			CreatedAt:          node.CreatedAt,
		}
	}
	return out, nil
}

// ListByZoneID lists all nodes in a zone.
func (p *peers) ListByZoneID(ctx context.Context, zoneID string) ([]Node, error) {
	q := models.New(p.db.Read())
	nodes, err := q.ListNodesByZone(ctx, sql.NullString{String: zoneID, Valid: true})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []Node{}, nil
		}
		return nil, err
	}
	out := make([]Node, len(nodes))
	for i, node := range nodes {
		var key wgtypes.Key
		if node.PublicKey.Valid {
			key, err = wgtypes.ParseKey(node.PublicKey.String)
			if err != nil {
				return nil, fmt.Errorf("parse node public key: %w", err)
			}
		}
		var wireguardEndpoints []string
		if node.WireguardEndpoints.Valid {
			wireguardEndpoints = strings.Split(node.WireguardEndpoints.String, ",")
		}
		var networkv4, networkv6 netip.Prefix
		if node.PrivateAddressV4 != "" {
			networkv4, err = netip.ParsePrefix(node.PrivateAddressV4)
			if err != nil {
				return nil, fmt.Errorf("parse node network IPv4: %w", err)
			}
		}
		if node.PrivateAddressV6 != "" {
			networkv6, err = netip.ParsePrefix(node.PrivateAddressV6)
			if err != nil {
				return nil, fmt.Errorf("parse node network IPv6: %w", err)
			}
		}
		out[i] = Node{
			ID:                 node.ID,
			PublicKey:          key,
			PrimaryEndpoint:    node.PrimaryEndpoint.String,
			WireGuardEndpoints: wireguardEndpoints,
			ZoneAwarenessID:    node.ZoneAwarenessID.String,
			PrivateIPv4:        networkv4,
			PrivateIPv6:        networkv6,
			GRPCPort:           int(node.GrpcPort),
			RaftPort:           int(node.RaftPort),
			UpdatedAt:          node.UpdatedAt,
			CreatedAt:          node.CreatedAt,
		}
	}
	return out, nil
}

// ListIDs returns a list of node IDs.
func (p *peers) ListIDs(ctx context.Context) ([]string, error) {
	ids, err := models.New(p.db.Read()).ListNodeIDs(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("list node IDs: %w", err)
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
