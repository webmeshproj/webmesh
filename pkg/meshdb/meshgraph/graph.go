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

// Package meshgraph provides an interface for maintaining a cyclic DAG of nodes.
package meshgraph

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"

	"github.com/dominikbraun/graph"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gitlab.com/webmesh/node/pkg/meshdb"
	"gitlab.com/webmesh/node/pkg/meshdb/models/raftdb"
)

type Graph graph.Graph[string, Node]

// ErrReadOnly is returned when a MeshDAG is not configured
// with a write interface.
var ErrReadOnly = errors.New("meshdag: read only")

// MeshGraph is the interface for maintaining a DAG of nodes.
type MeshGraph interface {
	// AddEdge adds an edge between two nodes.
	AddEdge(ctx context.Context, from, to string) error
	// RemoveEdge removes an edge between two nodes.
	RemoveEdge(ctx context.Context, from, to string) error
	// Build constructs a Graph from the database.
	Build(ctx context.Context) (Graph, error)
}

// New returns a new MeshDAG.
func New(store meshdb.Store) MeshGraph {
	return &meshDAG{
		rdb: raftdb.New(store.ReadDB()),
		wdb: raftdb.New(store.DB()),
	}
}

type meshDAG struct {
	rdb raftdb.Querier
	wdb raftdb.Querier
}

// AddEdge adds an edge between two nodes.
func (m *meshDAG) AddEdge(ctx context.Context, from, to string) error {
	if m.wdb == nil {
		return ErrReadOnly
	}
	if from == to {
		return nil
	}
	// Save the raft log some trouble by checking if the edge already exists.
	_, err := m.rdb.NodeEdgeExists(ctx, raftdb.NodeEdgeExistsParams{
		SrcNodeID: from,
		DstNodeID: to,
	})
	if err == nil {
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	return m.wdb.InsertNodeEdge(ctx, raftdb.InsertNodeEdgeParams{
		SrcNodeID: from,
		DstNodeID: to,
	})
}

// RemoveEdge removes an edge between two nodes.
func (m *meshDAG) RemoveEdge(ctx context.Context, from, to string) error {
	if m.wdb == nil {
		return ErrReadOnly
	}
	// Save the raft log some trouble by checking if the edge already exists.
	_, err := m.rdb.NodeEdgeExists(ctx, raftdb.NodeEdgeExistsParams{
		SrcNodeID: from,
		DstNodeID: to,
	})
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	return m.wdb.DeleteNodeEdge(ctx, raftdb.DeleteNodeEdgeParams{
		SrcNodeID: from,
		DstNodeID: to,
	})
}

// Node is a node in the DAG.
type Node struct {
	ID             string
	PublicKey      wgtypes.Key
	PublicEndpoint netip.AddrPort
	PrivateIPv4    netip.Prefix
	PrivateIPv6    netip.Prefix
}

// Build constructs a Graph from the database.
func (m *meshDAG) Build(ctx context.Context) (Graph, error) {
	g := graph.New(func(n Node) string {
		return n.ID
	})
	nodes, err := m.rdb.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	edges, err := m.rdb.ListNodeEdges(ctx)
	if err != nil {
		return nil, err
	}
	for _, node := range nodes {
		_ = g.AddVertex(Node{
			ID: node.ID,
			PublicKey: func() wgtypes.Key {
				key, _ := wgtypes.ParseKey(node.PublicKey.String)
				return key
			}(),
			PublicEndpoint: func() netip.AddrPort {
				addr, err := netip.ParseAddr(node.PublicEndpoint.String)
				if err == nil {
					return netip.AddrPortFrom(addr, uint16(node.WireguardPort))
				}
				return netip.AddrPort{}
			}(),
			PrivateIPv4: func() netip.Prefix {
				prefix, err := netip.ParsePrefix(node.PrivateAddressV4)
				if err == nil {
					return netip.PrefixFrom(prefix.Addr(), 32)
				}
				return netip.Prefix{}
			}(),
			PrivateIPv6: func() netip.Prefix {
				prefix, _ := netip.ParsePrefix(node.NetworkIpv6.String)
				return prefix
			}(),
		})
	}
	for _, edge := range edges {
		_ = g.AddEdge(edge.SrcNodeID, edge.DstNodeID)
	}
	return g, nil
}
