/*
Copyright 2023.

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
	"time"

	"github.com/dominikbraun/graph"
	"github.com/dominikbraun/graph/draw"
	"github.com/google/go-cmp/cmp"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gitlab.com/webmesh/node/pkg/meshdb"
	"gitlab.com/webmesh/node/pkg/meshdb/models/raftdb"
)

// ErrNodeNotFound is returned when a node is not found.
var ErrNodeNotFound = errors.New("node not found")

// Graph is the graph.Graph implementation for the mesh network.
type Graph graph.Graph[string, Node]

func graphHasher(n Node) string { return n.ID }

// Peers is the peers interface.
type Peers interface {
	// Graph returns the graph of nodes.
	Graph() Graph
	// Put creates or updates a node.
	Put(ctx context.Context, opts *PutOptions) (Node, error)
	// Get gets a node by ID.
	Get(ctx context.Context, id string) (Node, error)
	// Delete deletes a node.
	Delete(ctx context.Context, id string) error
	// List lists all nodes.
	List(ctx context.Context) ([]Node, error)
	// ListIDs lists all node IDs.
	ListIDs(ctx context.Context) ([]string, error)
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
	// PublicEndpoint is the primary public endpoint of the node.
	PublicEndpoint netip.Addr
	// PrivateIPv4 is the node's private IPv4 address.
	PrivateIPv4 netip.Prefix
	// NetworkIPv6 is the node's IPv6 network.
	NetworkIPv6 netip.Prefix
	// GRPCPort is the node's GRPC port.
	GRPCPort int
	// RaftPort is the node's Raft port.
	RaftPort int
	// WireguardPort is the node's Wireguard port.
	WireguardPort int
	// CreatedAt is the time the node was created.
	CreatedAt time.Time
	// UpdatedAt is the time the node was last updated.
	UpdatedAt time.Time
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

// CreateOptions are options for creating a node.
type PutOptions struct {
	// ID is the node's ID.
	ID string
	// PublicKey is the node's public key.
	PublicKey wgtypes.Key
	// PublicEndpoint is the primary public endpoint of the node.
	PublicEndpoint netip.Addr
	// NetworkIPv6 is true if the node's network is IPv6.
	NetworkIPv6 netip.Prefix
	// GRPCPort is the node's GRPC port.
	GRPCPort int
	// RaftPort is the node's Raft port.
	RaftPort int
	// WireguardPort is the node's Wireguard port.
	WireguardPort int
}

// New returns a new Peers interface.
func New(store meshdb.Store) Peers {
	return &peers{
		store: store,
		graph: NewGraph(store),
	}
}

type peers struct {
	store meshdb.Store
	graph Graph
}

func (p *peers) Graph() Graph { return p.graph }

func (p *peers) Put(ctx context.Context, opts *PutOptions) (Node, error) {
	err := p.graph.AddVertex(Node{
		ID:             opts.ID,
		PublicKey:      opts.PublicKey,
		PublicEndpoint: opts.PublicEndpoint,
		NetworkIPv6:    opts.NetworkIPv6,
		GRPCPort:       opts.GRPCPort,
		RaftPort:       opts.RaftPort,
		WireguardPort:  opts.WireguardPort,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
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
		q := raftdb.New(p.store.DB())
		err = q.DeleteNodeEdges(ctx, raftdb.DeleteNodeEdgesParams{
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
	q := raftdb.New(p.store.ReadDB())
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
		var primaryEndpoint netip.Addr
		if node.PublicEndpoint.Valid {
			primaryEndpoint, err = netip.ParseAddr(node.PublicEndpoint.String)
			if err != nil {
				return nil, fmt.Errorf("parse node endpoint: %w", err)
			}
		}
		var networkv4, networkv6 netip.Prefix
		if node.PrivateAddressV4 != "" {
			networkv4, err = netip.ParsePrefix(node.PrivateAddressV4)
			if err != nil {
				return nil, fmt.Errorf("parse node network IPv4: %w", err)
			}
		}
		if node.NetworkIpv6.Valid {
			networkv6, err = netip.ParsePrefix(node.NetworkIpv6.String)
			if err != nil {
				return nil, fmt.Errorf("parse node network IPv6: %w", err)
			}
		}
		out[i] = Node{
			ID:             node.ID,
			PublicKey:      key,
			PublicEndpoint: primaryEndpoint,
			PrivateIPv4:    networkv4,
			NetworkIPv6:    networkv6,
			GRPCPort:       int(node.GrpcPort),
			RaftPort:       int(node.RaftPort),
			WireguardPort:  int(node.WireguardPort),
			UpdatedAt:      node.UpdatedAt,
			CreatedAt:      node.CreatedAt,
		}
	}
	return out, nil
}

// ListIDs returns a list of node IDs.
func (p *peers) ListIDs(ctx context.Context) ([]string, error) {
	ids, err := raftdb.New(p.store.ReadDB()).ListNodeIDs(ctx)
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
		if graphEdge.Properties.Weight != edge.Weight {
			return p.graph.UpdateEdge(edge.From, edge.To, opts...)
		}
		return nil
	}
	if !errors.Is(err, graph.ErrEdgeNotFound) {
		return fmt.Errorf("get edge: %w", err)
	}
	err = p.graph.AddEdge(edge.From, edge.To, opts...)
	if err == nil {
		return nil
	}
	if !errors.Is(err, graph.ErrEdgeAlreadyExists) {
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
