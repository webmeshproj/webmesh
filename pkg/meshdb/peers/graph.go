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

package peers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/dominikbraun/graph"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"gitlab.com/webmesh/node/pkg/meshdb"
	"gitlab.com/webmesh/node/pkg/meshdb/models/raftdb"
)

// GraphStore implements graph.Store[string, Node] where
// string is the node ID and Node is the node itself.
type GraphStore struct {
	rdb raftdb.Querier
	wdb raftdb.Querier
}

// NewGraph creates a new Graph instance.
func NewGraph(store meshdb.Store) Graph {
	return graph.NewWithStore(graphHasher, NewGraphStore(store))
}

// NewGraphStore creates a new GraphStore instance.
func NewGraphStore(store meshdb.Store) graph.Store[string, Node] {
	return graph.Store[string, Node](&GraphStore{
		rdb: raftdb.New(store.ReadDB()),
		wdb: raftdb.New(store.DB()),
	})
}

// AddVertex should add the given vertex with the given hash value and vertex properties to the
// graph. If the vertex already exists, it is up to you whether ErrVertexAlreadyExists or no
// error should be returned.
func (g *GraphStore) AddVertex(nodeID string, node Node, props graph.VertexProperties) error {
	params := raftdb.InsertNodeParams{
		ID: node.ID,
		PublicKey: sql.NullString{
			String: node.PublicKey.String(),
			Valid:  true,
		},
		GrpcPort:      int64(node.GRPCPort),
		RaftPort:      int64(node.RaftPort),
		WireguardPort: int64(node.WireguardPort),
		CreatedAt:     node.CreatedAt,
		UpdatedAt:     node.UpdatedAt,
	}
	if node.NetworkIPv6.IsValid() {
		params.NetworkIpv6 = sql.NullString{
			String: node.NetworkIPv6.String(),
			Valid:  true,
		}
	}
	if node.PublicEndpoint.IsValid() {
		params.PublicEndpoint = sql.NullString{
			String: node.PublicEndpoint.String(),
			Valid:  true,
		}
	}
	_, err := g.wdb.InsertNode(context.Background(), params)
	if err != nil {
		var sqliteErr *sqlite.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3.SQLITE_CONSTRAINT {
			return graph.ErrVertexAlreadyExists
		}
		return fmt.Errorf("create node: %w", err)
	}
	return nil
}

// Vertex should return the vertex and vertex properties with the given hash value. If the
// vertex doesn't exist, ErrVertexNotFound should be returned.
func (g *GraphStore) Vertex(nodeID string) (node Node, props graph.VertexProperties, err error) {
	dbnode, err := g.rdb.GetNode(context.Background(), nodeID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = graph.ErrVertexNotFound
		}
		return
	}
	node.ID = dbnode.ID
	node.GRPCPort = int(dbnode.GrpcPort)
	node.RaftPort = int(dbnode.RaftPort)
	node.WireguardPort = int(dbnode.WireguardPort)
	node.CreatedAt = dbnode.CreatedAt
	node.UpdatedAt = dbnode.UpdatedAt
	if dbnode.PublicKey.Valid {
		node.PublicKey, err = wgtypes.ParseKey(dbnode.PublicKey.String)
		if err != nil {
			err = fmt.Errorf("parse node public key: %w", err)
			return
		}
	}
	if dbnode.PublicEndpoint.Valid {
		node.PublicEndpoint, err = netip.ParseAddr(dbnode.PublicEndpoint.String)
		if err != nil {
			err = fmt.Errorf("parse node endpoint: %w", err)
			return
		}
	}
	if dbnode.PrivateAddressV4 != "" {
		node.PrivateIPv4, err = netip.ParsePrefix(dbnode.PrivateAddressV4)
		if err != nil {
			err = fmt.Errorf("parse node private IPv4: %w", err)
			return
		}
		// We are saving the full prefix length to the database so we need to
		// truncate it to 32 bits here.
		node.PrivateIPv4 = netip.PrefixFrom(node.PrivateIPv4.Addr(), 32)
	}
	if dbnode.NetworkIpv6.Valid {
		node.NetworkIPv6, err = netip.ParsePrefix(dbnode.NetworkIpv6.String)
		if err != nil {
			err = fmt.Errorf("parse node private IPv6: %w", err)
			return
		}
	}
	return
}

// RemoveVertex should remove the vertex with the given hash value. If the vertex doesn't
// exist, ErrVertexNotFound should be returned. If the vertex has edges to other vertices,
// ErrVertexHasEdges should be returned.
func (g *GraphStore) RemoveVertex(nodeID string) error {
	_, err := g.rdb.GetNode(context.Background(), nodeID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = graph.ErrVertexNotFound
		}
		return err
	}
	_, err = g.rdb.NodeHasEdges(context.Background(), raftdb.NodeHasEdgesParams{
		SrcNodeID: nodeID,
		DstNodeID: nodeID,
	})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check node edges: %w", err)
	} else if err == nil {
		return graph.ErrVertexHasEdges
	}
	if err := g.wdb.DeleteNode(context.Background(), nodeID); err != nil {
		return fmt.Errorf("delete node: %w", err)
	}
	return nil
}

// ListVertices should return all vertices in the graph in a slice.
func (g *GraphStore) ListVertices() ([]string, error) {
	ids, err := g.rdb.ListNodeIDs(context.Background())
	if err != nil {
		if err == sql.ErrNoRows {
			return []string{}, nil
		}
		return nil, fmt.Errorf("list node IDs: %w", err)
	}
	return ids, nil
}

// VertexCount should return the number of vertices in the graph. This should be equal to the
// length of the slice returned by ListVertices.
func (g *GraphStore) VertexCount() (int, error) {
	count, err := g.rdb.GetNodeCount(context.Background())
	if err != nil {
		return 0, fmt.Errorf("get node count: %w", err)
	}
	return int(count), nil
}

// AddEdge should add an edge between the vertices with the given source and target hashes.
//
// If either vertex doesn't exit, ErrVertexNotFound should be returned for the respective
// vertex. If the edge already exists, ErrEdgeAlreadyExists should be returned.
func (g *GraphStore) AddEdge(sourceNode, targetNode string, edge graph.Edge[string]) error {
	_, err := g.rdb.EitherNodeExists(context.Background(), raftdb.EitherNodeExistsParams{
		ID:   sourceNode,
		ID_2: targetNode,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			err = graph.ErrVertexNotFound
		}
		return err
	}
	params := raftdb.InsertNodeEdgeParams{
		SrcNodeID: sourceNode,
		DstNodeID: targetNode,
		Weight:    int64(edge.Properties.Weight),
	}
	if edge.Properties.Attributes != nil {
		attrs, err := json.Marshal(edge.Properties.Attributes)
		if err != nil {
			return fmt.Errorf("marshal edge attributes: %w", err)
		}
		params.Attrs = sql.NullString{
			String: string(attrs),
			Valid:  true,
		}
	}
	err = g.wdb.InsertNodeEdge(context.Background(), params)
	if err != nil {
		var sqlerr *sqlite.Error
		if errors.As(err, &sqlerr) && sqlerr.Code() == sqlite3.SQLITE_CONSTRAINT {
			return graph.ErrEdgeAlreadyExists
		}
		return fmt.Errorf("insert node edge: %w", err)
	}
	return nil
}

// UpdateEdge should update the edge between the given vertices with the data of the given
// Edge instance. If the edge doesn't exist, ErrEdgeNotFound should be returned.
func (g *GraphStore) UpdateEdge(sourceNode, targetNode string, edge graph.Edge[string]) error {
	_, err := g.rdb.NodeEdgeExists(context.Background(), raftdb.NodeEdgeExistsParams{
		SrcNodeID: sourceNode,
		DstNodeID: targetNode,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return graph.ErrEdgeNotFound
		}
		return fmt.Errorf("get node edge: %w", err)
	}
	params := raftdb.UpdateNodeEdgeParams{
		SrcNodeID: sourceNode,
		DstNodeID: targetNode,
		Weight:    int64(edge.Properties.Weight),
	}
	if edge.Properties.Attributes != nil {
		attrs, err := json.Marshal(edge.Properties.Attributes)
		if err != nil {
			return fmt.Errorf("marshal edge attributes: %w", err)
		}
		params.Attrs = sql.NullString{
			String: string(attrs),
			Valid:  true,
		}
	}
	err = g.wdb.UpdateNodeEdge(context.Background(), params)
	if err != nil {
		return fmt.Errorf("update node edge: %w", err)
	}
	return nil
}

// RemoveEdge should remove the edge between the vertices with the given source and target
// hashes.
//
// If either vertex doesn't exist, it is up to you whether ErrVertexNotFound or no error should
// be returned. If the edge doesn't exist, it is up to you whether ErrEdgeNotFound or no error
// should be returned.
func (g *GraphStore) RemoveEdge(sourceNode, targetNode string) error {
	return g.wdb.DeleteNodeEdge(context.Background(), raftdb.DeleteNodeEdgeParams{
		SrcNodeID: sourceNode,
		DstNodeID: targetNode,
	})
}

// Edge should return the edge joining the vertices with the given hash values. It should
// exclusively look for an edge between the source and the target vertex, not vice versa. The
// graph implementation does this for undirected graphs itself.
//
// Note that unlike Graph.Edge, this function is supposed to return an Edge[K], i.e. an edge
// that only contains the vertex hashes instead of the vertices themselves.
//
// If the edge doesn't exist, ErrEdgeNotFound should be returned.
func (g *GraphStore) Edge(sourceNode, targetNode string) (graph.Edge[string], error) {
	edge, err := g.rdb.GetNodeEdge(context.Background(), raftdb.GetNodeEdgeParams{
		SrcNodeID: sourceNode,
		DstNodeID: targetNode,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return graph.Edge[string]{}, graph.ErrEdgeNotFound
		}
		return graph.Edge[string]{}, fmt.Errorf("get node edge: %w", err)
	}
	var attrs map[string]string
	if edge.Attrs.Valid {
		err = json.Unmarshal([]byte(edge.Attrs.String), &attrs)
		if err != nil {
			return graph.Edge[string]{}, fmt.Errorf("unmarshal edge attributes: %w", err)
		}
	}
	return graph.Edge[string]{
		Source: sourceNode,
		Target: targetNode,
		Properties: graph.EdgeProperties{
			Attributes: attrs,
			Weight:     int(edge.Weight),
		},
	}, nil
}

// ListEdges should return all edges in the graph in a slice.
func (g *GraphStore) ListEdges() ([]graph.Edge[string], error) {
	edges, err := g.rdb.ListNodeEdges(context.Background())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return []graph.Edge[string]{}, nil
		}
		return nil, fmt.Errorf("list node edges: %w", err)
	}
	out := make([]graph.Edge[string], len(edges))
	for i, edge := range edges {
		var attrs map[string]string
		if edge.Attrs.Valid {
			err = json.Unmarshal([]byte(edge.Attrs.String), &attrs)
			if err != nil {
				return nil, fmt.Errorf("unmarshal edge attributes: %w", err)
			}
		}
		out[i] = graph.Edge[string]{
			Source: edge.SrcNodeID,
			Target: edge.DstNodeID,
			Properties: graph.EdgeProperties{
				Attributes: attrs,
				Weight:     int(edge.Weight),
			},
		}
	}
	return out, nil
}
