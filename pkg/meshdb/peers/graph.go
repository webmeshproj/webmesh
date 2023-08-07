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

package peers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dominikbraun/graph"

	"github.com/webmeshproj/webmesh/pkg/storage"
)

// GraphStore implements graph.Store[string, Node] where
// string is the node ID and Node is the node itself.
type GraphStore struct {
	storage.Storage
}

// NodesPrefix is where nodes are stored in the database.
// nodes are indexed by their ID in the format /registry/nodes/<id>.
const NodesPrefix = "/registry/nodes"

// EdgesPrefix is where edges are stored in the database.
// edges are indexed by their source and target node IDs
// in the format /registry/edges/<source>/<target>.
const EdgesPrefix = "/registry/edges"

// NewGraph creates a new Graph instance.
func NewGraph(st storage.Storage) Graph {
	return graph.NewWithStore(graphHasher, NewGraphStore(st))
}

// NewGraphStore creates a new GraphStore instance.
func NewGraphStore(st storage.Storage) graph.Store[string, Node] {
	return graph.Store[string, Node](&GraphStore{st})
}

// AddVertex should add the given vertex with the given hash value and vertex properties to the
// graph. If the vertex already exists, it is up to you whether ErrVertexAlreadyExists or no
// error should be returned.
func (g *GraphStore) AddVertex(nodeID string, node Node, props graph.VertexProperties) error {
	data, err := json.Marshal(node)
	if err != nil {
		return fmt.Errorf("marshal node: %w", err)
	}
	key := fmt.Sprintf("%s/%s", NodesPrefix, nodeID)
	if err := g.Put(context.Background(), key, string(data), 0); err != nil {
		return fmt.Errorf("put node: %w", err)
	}
	return nil
}

// Vertex should return the vertex and vertex properties with the given hash value. If the
// vertex doesn't exist, ErrVertexNotFound should be returned.
func (g *GraphStore) Vertex(nodeID string) (node Node, props graph.VertexProperties, err error) {
	key := fmt.Sprintf("%s/%s", NodesPrefix, nodeID)
	data, err := g.Get(context.Background(), key)
	if err != nil {
		if errors.Is(err, storage.ErrKeyNotFound) {
			err = graph.ErrVertexNotFound
		}
		return
	}
	err = json.Unmarshal([]byte(data), &node)
	if err != nil {
		err = fmt.Errorf("unmarshal node: %w", err)
	}
	return
}

// RemoveVertex should remove the vertex with the given hash value. If the vertex doesn't
// exist, ErrVertexNotFound should be returned. If the vertex has edges to other vertices,
// ErrVertexHasEdges should be returned.
func (g *GraphStore) RemoveVertex(nodeID string) error {
	key := fmt.Sprintf("%s/%s", NodesPrefix, nodeID)
	_, err := g.Get(context.Background(), key)
	if err != nil {
		if errors.Is(err, storage.ErrKeyNotFound) {
			err = graph.ErrVertexNotFound
		}
		return err
	}
	// Check if the node has edges.
	keys, err := g.List(context.Background(), EdgesPrefix)
	if err != nil {
		return fmt.Errorf("list edges: %w", err)
	}
	for _, key := range keys {
		key = strings.TrimPrefix(key, EdgesPrefix+"/")
		parts := strings.Split(key, "/")
		if len(parts) != 2 {
			// Should never happen.
			continue
		}
		if parts[0] == nodeID || parts[1] == nodeID {
			return graph.ErrVertexHasEdges
		}
	}
	if err := g.Delete(context.Background(), key); err != nil {
		return fmt.Errorf("delete node: %w", err)
	}
	return nil
}

// ListVertices should return all vertices in the graph in a slice.
func (g *GraphStore) ListVertices() ([]string, error) {
	keys, err := g.List(context.Background(), NodesPrefix)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	out := make([]string, len(keys))
	for i, key := range keys {
		out[i] = strings.TrimPrefix(key, NodesPrefix+"/")
	}
	return out, nil
}

// VertexCount should return the number of vertices in the graph. This should be equal to the
// length of the slice returned by ListVertices.
func (g *GraphStore) VertexCount() (int, error) {
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
func (g *GraphStore) AddEdge(sourceNode, targetNode string, edge graph.Edge[string]) error {
	// We diverge from the suggested implementation and only check that one of the nodes
	// exists. This is so joiners can add edges to nodes that are not yet in the graph.
	// If this ends up causing problems, we can change it.
	nodeKeys, err := g.List(context.Background(), NodesPrefix)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	edgeKeys, err := g.List(context.Background(), EdgesPrefix)
	if err != nil {
		return fmt.Errorf("list edges: %w", err)
	}
	var vertexExists bool
	for _, key := range nodeKeys {
		key = strings.TrimPrefix(key, NodesPrefix+"/")
		if key == sourceNode || key == targetNode {
			vertexExists = true
			break
		}
	}
	if !vertexExists {
		return graph.ErrVertexNotFound
	}
	var edgeExists bool
	for _, key := range edgeKeys {
		key = strings.TrimPrefix(key, EdgesPrefix+"/")
		parts := strings.Split(key, "/")
		if len(parts) != 2 {
			// Should never happen.
			continue
		}
		if parts[0] == sourceNode && parts[1] == targetNode {
			edgeExists = true
			break
		}
	}
	if edgeExists {
		return graph.ErrEdgeAlreadyExists
	}
	edgeKey := fmt.Sprintf("%s/%s/%s", EdgesPrefix, sourceNode, targetNode)
	edgeData, err := json.Marshal(Edge{
		From:   sourceNode,
		To:     targetNode,
		Weight: int(edge.Properties.Weight),
		Attrs:  edge.Properties.Attributes,
	})
	if err != nil {
		return fmt.Errorf("marshal edge: %w", err)
	}
	err = g.Put(context.Background(), edgeKey, string(edgeData), 0)
	if err != nil {
		return fmt.Errorf("put node edge: %w", err)
	}
	return nil
}

// UpdateEdge should update the edge between the given vertices with the data of the given
// Edge instance. If the edge doesn't exist, ErrEdgeNotFound should be returned.
func (g *GraphStore) UpdateEdge(sourceNode, targetNode string, edge graph.Edge[string]) error {
	key := fmt.Sprintf("%s/%s/%s", EdgesPrefix, sourceNode, targetNode)
	_, err := g.Get(context.Background(), key)
	if err != nil {
		if errors.Is(err, storage.ErrKeyNotFound) {
			return graph.ErrEdgeNotFound
		}
		return fmt.Errorf("get node edge: %w", err)
	}
	edgeData, err := json.Marshal(Edge{
		From:   sourceNode,
		To:     targetNode,
		Weight: int(edge.Properties.Weight),
		Attrs:  edge.Properties.Attributes,
	})
	if err != nil {
		return fmt.Errorf("marshal edge: %w", err)
	}
	err = g.Put(context.Background(), key, string(edgeData), 0)
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
func (g *GraphStore) RemoveEdge(sourceNode, targetNode string) error {
	key := fmt.Sprintf("%s/%s/%s", EdgesPrefix, sourceNode, targetNode)
	err := g.Delete(context.Background(), key)
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
func (g *GraphStore) Edge(sourceNode, targetNode string) (graph.Edge[string], error) {
	key := fmt.Sprintf("%s/%s/%s", EdgesPrefix, sourceNode, targetNode)
	data, err := g.Get(context.Background(), key)
	if err != nil {
		if errors.Is(err, storage.ErrKeyNotFound) {
			return graph.Edge[string]{}, graph.ErrEdgeNotFound
		}
		return graph.Edge[string]{}, fmt.Errorf("get node edge: %w", err)
	}
	var edge Edge
	err = json.Unmarshal([]byte(data), &edge)
	if err != nil {
		return graph.Edge[string]{}, fmt.Errorf("unmarshal edge: %w", err)
	}
	return graph.Edge[string]{
		Source: sourceNode,
		Target: targetNode,
		Properties: graph.EdgeProperties{
			Attributes: edge.Attrs,
			Weight:     int(edge.Weight),
		},
	}, nil
}

// ListEdges should return all edges in the graph in a slice.
func (g *GraphStore) ListEdges() ([]graph.Edge[string], error) {
	edges := make([]graph.Edge[string], 0)
	err := g.IterPrefix(context.Background(), EdgesPrefix, func(_, value string) error {
		var edge Edge
		err := json.Unmarshal([]byte(value), &edge)
		if err != nil {
			return fmt.Errorf("unmarshal edge: %w", err)
		}
		edges = append(edges, graph.Edge[string]{
			Source: edge.From,
			Target: edge.To,
			Properties: graph.EdgeProperties{
				Attributes: edge.Attrs,
				Weight:     int(edge.Weight),
			},
		})
		return nil
	})
	return edges, err
}
