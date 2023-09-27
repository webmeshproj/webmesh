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

// Package graph implements a graph data structure for the mesh network.
package graph

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/dominikbraun/graph"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	dbutil "github.com/webmeshproj/webmesh/pkg/meshdb/util"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/backends/badgerdb"
)

// NodeID is the type of a node ID.
type NodeID string

// String returns the string representation of the node ID.
func (id NodeID) String() string { return string(id) }

// Bytes returns the byte representation of the node ID.
func (id NodeID) Bytes() []byte { return []byte(id) }

// IsEmpty returns true if the node ID is empty.
func (id NodeID) IsEmpty() bool { return id == "" }

// Graph is the graph.Graph implementation for the mesh network.
type Graph graph.Graph[NodeID, MeshNode]

// GraphStore implements graph.Store[string, Node] where
// string is the node ID and Node is the node itself.
type GraphStore struct {
	storage.MeshStorage
	mu sync.RWMutex
}

// NodesPrefix is where nodes are stored in the database.
// nodes are indexed by their ID in the format /registry/nodes/<id>.
var NodesPrefix = storage.RegistryPrefix.ForString("nodes")

// EdgesPrefix is where edges are stored in the database.
// edges are indexed by their source and target node IDs
// in the format /registry/edges/<source>/<target>.
var EdgesPrefix = storage.RegistryPrefix.ForString("edges")

// NewGraph creates a new Graph instance.
func NewGraph(st storage.MeshStorage) Graph {
	return graph.NewWithStore(graphHasher, newGraphStore(st))
}

// NewTestGraph is an alias for creating a new graph with in-memory storage.
func NewTestGraph() (Graph, error) {
	memdb, err := badgerdb.NewInMemory(badgerdb.Options{})
	if err != nil {
		return nil, fmt.Errorf("create in-memory database: %w", err)
	}
	return NewGraph(memdb), nil
}

// newGraphStore creates a new GraphStore instance.
func newGraphStore(st storage.MeshStorage) graph.Store[NodeID, MeshNode] {
	return graph.Store[NodeID, MeshNode](&GraphStore{MeshStorage: st})
}

// graphHasher is the hash key function for the graph.
func graphHasher(n MeshNode) NodeID { return NodeID(n.GetId()) }

// BuildAdjacencyMap returns the adjacency map for the graph.
func BuildAdjacencyMap(g Graph) (AdjacencyMap, error) {
	m, err := g.AdjacencyMap()
	if err != nil {
		return nil, fmt.Errorf("get adjacency map: %w", err)
	}
	out := make(AdjacencyMap, len(m))
	for source, targets := range m {
		out[source] = make(map[NodeID]Edge, len(targets))
		for target, edge := range targets {
			out[source][target] = Edge(edge)
		}
	}
	return out, nil
}

// AddVertex should add the given vertex with the given hash value and vertex properties to the
// graph. If the vertex already exists, it is up to you whether ErrVertexAlreadyExists or no
// error should be returned.
func (g *GraphStore) AddVertex(nodeID NodeID, node MeshNode, props graph.VertexProperties) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	ctx := context.Background()
	if nodeID.IsEmpty() {
		return fmt.Errorf("node ID must not be empty")
	}
	if !dbutil.IsValidNodeID(nodeID.String()) {
		return fmt.Errorf("invalid node ID: %s", nodeID)
	}
	if node.PublicKey != "" {
		// Make sure it's a valid public key.
		_, err := crypto.DecodePublicKey(node.PublicKey)
		if err != nil {
			return fmt.Errorf("invalid public key: %w", err)
		}
	}
	data, err := node.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal node: %w", err)
	}
	key := NodesPrefix.For(nodeID.Bytes())
	if err := g.PutValue(ctx, key, data, 0); err != nil {
		return fmt.Errorf("put node: %w", err)
	}
	return nil
}

// Vertex should return the vertex and vertex properties with the given hash value. If the
// vertex doesn't exist, ErrVertexNotFound should be returned.
func (g *GraphStore) Vertex(nodeID NodeID) (node MeshNode, props graph.VertexProperties, err error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	ctx := context.Background()
	if nodeID.IsEmpty() {
		err = fmt.Errorf("node ID must not be empty")
		return
	}
	key := NodesPrefix.For(nodeID.Bytes())
	data, err := g.GetValue(ctx, key)
	if err != nil {
		if errors.Is(err, storage.ErrKeyNotFound) {
			err = graph.ErrVertexNotFound
		}
		return
	}
	err = node.UnmarshalJSON(data)
	if err != nil {
		err = fmt.Errorf("unmarshal node: %w", err)
	}
	return
}

// RemoveVertex should remove the vertex with the given hash value. If the vertex doesn't
// exist, ErrVertexNotFound should be returned. If the vertex has edges to other vertices,
// ErrVertexHasEdges should be returned.
func (g *GraphStore) RemoveVertex(nodeID NodeID) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	ctx := context.Background()
	if nodeID.IsEmpty() {
		return fmt.Errorf("node ID must not be empty")
	}
	key := NodesPrefix.For(nodeID.Bytes())
	_, err := g.GetValue(ctx, key)
	if err != nil {
		if errors.Is(err, storage.ErrKeyNotFound) {
			err = graph.ErrVertexNotFound
		}
		return err
	}
	// Check if the node has edges.
	keys, err := g.ListKeys(ctx, EdgesPrefix)
	if err != nil {
		return fmt.Errorf("list edges: %w", err)
	}
	for _, key := range keys {
		key = EdgesPrefix.TrimFrom(key)
		parts := bytes.Split(key, []byte("/"))
		if len(parts) != 2 {
			// Should never happen.
			continue
		}
		if bytes.Equal(parts[0], nodeID.Bytes()) || bytes.Equal(parts[1], nodeID.Bytes()) {
			return graph.ErrVertexHasEdges
		}
	}
	if err := g.Delete(ctx, key); err != nil {
		return fmt.Errorf("delete node: %w", err)
	}
	return nil
}

// ListVertices should return all vertices in the graph in a slice.
func (g *GraphStore) ListVertices() ([]NodeID, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	ctx := context.Background()
	keys, err := g.ListKeys(ctx, NodesPrefix)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	out := make([]NodeID, 0)
	for _, key := range keys {
		if bytes.Equal(key, NodesPrefix) {
			continue
		}
		out = append(out, NodeID(bytes.TrimPrefix(key, append(NodesPrefix, '/'))))
	}
	return out, nil
}

// VertexCount should return the number of vertices in the graph. This should be equal to the
// length of the slice returned by ListVertices.
func (g *GraphStore) VertexCount() (int, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	ids, err := g.ListVertices()
	if err != nil {
		return 0, fmt.Errorf("list vertices: %w", err)
	}
	return len(ids), nil
}

// AddEdge should add an edge between the vertices with the given source and target hashes.
//
// If either vertex doesn't exit, ErrVertexNotFound should be returned for the respective
// vertex. If the edge already exists, ErrEdgeAlreadyExists should be returned.
func (g *GraphStore) AddEdge(sourceNode, targetNode NodeID, edge graph.Edge[NodeID]) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	ctx := context.Background()
	if sourceNode.IsEmpty() || targetNode.IsEmpty() {
		return fmt.Errorf("node ID must not be empty")
	}
	// We diverge from the suggested implementation and only check that one of the nodes
	// exists. This is so joiners can add edges to nodes that are not yet in the graph.
	// If this ends up causing problems, we can change it.
	nodeKeys, err := g.ListKeys(ctx, NodesPrefix)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	edgeKeys, err := g.ListKeys(ctx, EdgesPrefix)
	if err != nil {
		return fmt.Errorf("list edges: %w", err)
	}
	var vertexExists bool
	for _, key := range nodeKeys {
		key = NodesPrefix.TrimFrom(key)
		if bytes.Equal(key, sourceNode.Bytes()) || bytes.Equal(key, targetNode.Bytes()) {
			vertexExists = true
			break
		}
	}
	if !vertexExists {
		return graph.ErrVertexNotFound
	}
	var edgeExists bool
	for _, key := range edgeKeys {
		key = EdgesPrefix.TrimFrom(key)
		parts := bytes.Split(key, []byte("/"))
		if len(parts) != 2 {
			// Should never happen.
			continue
		}
		if bytes.Equal(parts[0], sourceNode.Bytes()) && bytes.Equal(parts[1], sourceNode.Bytes()) {
			edgeExists = true
			break
		}
	}
	if edgeExists {
		return graph.ErrEdgeAlreadyExists
	}
	key := newEdgeKey(sourceNode, targetNode)
	edgeData, err := Edge(edge).ToMeshEdge(sourceNode, targetNode).MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal edge: %w", err)
	}
	err = g.PutValue(ctx, key, edgeData, 0)
	if err != nil {
		return fmt.Errorf("put node edge: %w", err)
	}
	return nil
}

// UpdateEdge should update the edge between the given vertices with the data of the given
// Edge instance. If the edge doesn't exist, ErrEdgeNotFound should be returned.
func (g *GraphStore) UpdateEdge(sourceNode, targetNode NodeID, edge graph.Edge[NodeID]) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	ctx := context.Background()
	if sourceNode.IsEmpty() || targetNode.IsEmpty() {
		return fmt.Errorf("node ID must not be empty")
	}
	key := newEdgeKey(sourceNode, targetNode)
	_, err := g.GetValue(ctx, key)
	if err != nil {
		if errors.Is(err, storage.ErrKeyNotFound) {
			return graph.ErrEdgeNotFound
		}
		return fmt.Errorf("get node edge: %w", err)
	}
	edgeData, err := Edge(edge).ToMeshEdge(sourceNode, targetNode).MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal edge: %w", err)
	}
	err = g.PutValue(ctx, key, edgeData, 0)
	if err != nil {
		return fmt.Errorf("put node edge: %w", err)
	}
	return nil
}

// RemoveEdge should remove the edge between the vertices with the given source and target
// hashes.
//
// If either vertex doesn't exist, it is up to you whether ErrVertexNotFound or no error should
// be returned. If the edge doesn't exist, it is up to you whether ErrEdgeNotFound or no error
// should be returned.
func (g *GraphStore) RemoveEdge(sourceNode, targetNode NodeID) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	ctx := context.Background()
	if sourceNode.IsEmpty() || targetNode.IsEmpty() {
		return fmt.Errorf("node ID must not be empty")
	}
	key := newEdgeKey(sourceNode, targetNode)
	err := g.Delete(ctx, key)
	if err != nil {
		// Don't return an error if the edge doesn't exist.
		if errors.Is(err, storage.ErrKeyNotFound) {
			return nil
		}
		return fmt.Errorf("delete node edge: %w", err)
	}
	return nil
}

// Edge should return the edge joining the vertices with the given hash values. It should
// exclusively look for an edge between the source and the target vertex, not vice versa. The
// graph implementation does this for undirected graphs itself.
//
// Note that unlike Graph.Edge, this function is supposed to return an Edge[K], i.e. an edge
// that only contains the vertex hashes instead of the vertices themselves.
//
// If the edge doesn't exist, ErrEdgeNotFound should be returned.
func (g *GraphStore) Edge(sourceNode, targetNode NodeID) (graph.Edge[NodeID], error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	ctx := context.Background()
	if sourceNode.IsEmpty() || targetNode.IsEmpty() {
		return graph.Edge[NodeID]{}, fmt.Errorf("node ID must not be empty")
	}
	key := newEdgeKey(sourceNode, targetNode)
	data, err := g.GetValue(ctx, key)
	if err != nil {
		if errors.Is(err, storage.ErrKeyNotFound) {
			return graph.Edge[NodeID]{}, graph.ErrEdgeNotFound
		}
		return graph.Edge[NodeID]{}, fmt.Errorf("get node edge: %w", err)
	}
	var edge MeshEdge
	err = edge.UnmarshalJSON(data)
	if err != nil {
		return graph.Edge[NodeID]{}, fmt.Errorf("unmarshal edge: %w", err)
	}
	return edge.AsGraphEdge(), nil
}

// ListEdges should return all edges in the graph in a slice.
func (g *GraphStore) ListEdges() ([]graph.Edge[NodeID], error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	ctx := context.Background()
	edges := make([]graph.Edge[NodeID], 0)
	err := g.IterPrefix(ctx, EdgesPrefix, func(key, value []byte) error {
		if bytes.Equal(key, EdgesPrefix) {
			return nil
		}
		var edge MeshEdge
		err := edge.UnmarshalJSON(value)
		if err != nil {
			return fmt.Errorf("unmarshal edge: %w", err)
		}
		edges = append(edges, edge.AsGraphEdge())
		return nil
	})
	return edges, err
}

func newEdgeKey(source, target NodeID) []byte {
	return EdgesPrefix.For(source.Bytes()).For(target.Bytes())
}
