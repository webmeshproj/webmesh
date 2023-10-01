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

package testutil

import (
	"sort"
	"testing"
	"time"

	"github.com/dominikbraun/graph"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// NewGraphStoreFunc is a function that creates a new PeerGraphStore implementation.
type NewGraphStoreFunc func(t *testing.T) types.PeerGraphStore

// TestPeerGraphstoreConformance tests that a PeerGraphStore implementation conforms to the interface.
func TestPeerGraphstoreConformance(t *testing.T, builder NewGraphStoreFunc) {
	store := builder(t)

	t.Run("PeerGraphStoreConformance", func(t *testing.T) {
		// We don't currently use vertex properties, but they may be used in the future.
		t.Run("AddAndRemoveVerticies", func(t *testing.T) {
			t.Run("InvalidVertex", func(t *testing.T) {
				tc := []struct {
					name string
					node types.MeshNode
				}{
					{
						name: "no node ID",
						node: types.MeshNode{MeshNode: &v1.MeshNode{
							PublicKey: mustGeneratePublicKey(t),
						}},
					},
					{
						name: "invalid node ID",
						node: types.MeshNode{MeshNode: &v1.MeshNode{
							Id:        "invalid/node-id",
							PublicKey: mustGeneratePublicKey(t),
						}},
					},
					{
						name: "invalid public key",
						node: types.MeshNode{MeshNode: &v1.MeshNode{
							Id:        "node-id",
							PublicKey: "invalid",
						}},
					},
				}
				for _, c := range tc {
					testCase := c
					t.Run(testCase.name, func(t *testing.T) {
						if err := store.AddVertex(testCase.node.NodeID(), testCase.node, graph.VertexProperties{}); err == nil {
							t.Error("AddVertex did not fail")
						}
					})
				}
			})

			t.Run("ValidVertex", func(t *testing.T) {
				tc := []struct {
					name string
					node types.MeshNode
				}{
					{
						name: "valid-node-a",
						node: types.MeshNode{MeshNode: &v1.MeshNode{
							Id:        "valid-node-a",
							PublicKey: mustGeneratePublicKey(t),
						}},
					},
					{
						name: "valid-node-b",
						node: types.MeshNode{MeshNode: &v1.MeshNode{
							Id:        "valid-node-b",
							PublicKey: mustGeneratePublicKey(t),
						}},
					},
					{
						name: "valid-node-c",
						node: types.MeshNode{MeshNode: &v1.MeshNode{
							Id:        "valid-node-c",
							PublicKey: mustGeneratePublicKey(t),
						}},
					},
				}
				for _, c := range tc {
					testCase := c
					t.Run(testCase.name, func(t *testing.T) {
						// Make sure we can round-trip the node.
						if err := store.AddVertex(testCase.node.NodeID(), testCase.node, graph.VertexProperties{}); err != nil {
							t.Fatalf("AddVertex failed: %v", err)
						}
						// Make sure we can eventually get the node back.
						var node types.MeshNode
						var err error
						ok := Eventually[error](func() error {
							node, _, err = store.Vertex(testCase.node.NodeID())
							return err
						}).ShouldNotError(time.Second*15, time.Second)
						if !ok {
							t.Fatalf("Vertex failed: %v", err)
						}
						if node.MeshNode == nil {
							t.Errorf("Vertex is nil")
						}
						if !testCase.node.DeepEqual(node) {
							t.Errorf("Expected node %v, got %v", testCase.node, node)
						}
						// Remove the node.
						if err := store.RemoveVertex(testCase.node.NodeID()); err != nil {
							t.Fatalf("RemoveVertex failed: %v", err)
						}
						// The node should eventually be gone
						ok = Eventually[error](func() error {
							_, _, err = store.Vertex(testCase.node.NodeID())
							return err
						}).ShouldErrorWith(time.Second*15, time.Second, graph.ErrVertexNotFound)
						if !ok {
							t.Error("Vertex did not return ErrVertexNotFound, got:", err)
						}
					})
				}
			})

			t.Run("ListVerticies", func(t *testing.T) {
				nodes := []types.MeshNode{
					{
						MeshNode: &v1.MeshNode{
							Id:        "list-node-a",
							PublicKey: mustGeneratePublicKey(t),
						},
					},
					{
						MeshNode: &v1.MeshNode{
							Id:        "list-node-b",
							PublicKey: mustGeneratePublicKey(t),
						},
					},
				}
				for _, node := range nodes {
					if err := store.AddVertex(node.NodeID(), node, graph.VertexProperties{}); err != nil {
						t.Fatalf("AddVertex failed: %v", err)
					}
				}
				// We should eventually have 2 verticies
				var count int
				ok := Eventually[int](func() int {
					var err error
					count, err = store.VertexCount()
					if err != nil {
						t.Errorf("VertexCount failed: %v", err)
					}
					return count
				}).ShouldEqual(time.Second*15, time.Second, 2)
				if !ok {
					t.Fatalf("Expected 2 verticies, got %d", count)
				}
				vertexIDs, err := store.ListVertices()
				if err != nil {
					t.Errorf("ListVertices failed: %v", err)
				}
				if len(vertexIDs) != 2 {
					t.Errorf("Expected 2 verticies, got %d", len(vertexIDs))
				}
				// We should have the correct verticies
				expected := []string{nodes[0].NodeID().String(), nodes[1].NodeID().String()}
				sort.Strings(expected)
				actual := []string{vertexIDs[0].String(), vertexIDs[1].String()}
				sort.Strings(actual)
				if len(expected) != len(actual) {
					t.Errorf("Expected %v, got %v", expected, actual)
				}
				for i := range expected {
					if expected[i] != actual[i] {
						t.Errorf("Expected %v, got %v", expected, actual)
					}
				}
			})

			t.Run("RemoveNonExistingVertex", func(t *testing.T) {
				err := store.RemoveVertex(types.NodeID("non-existing"))
				if err == nil {
					t.Errorf("RemoveVertex did not fail")
				}
				if !errors.Is(err, graph.ErrVertexNotFound) {
					t.Errorf("Expected ErrVertexNotFound, got %v", err)
				}
			})

			t.Run("VertexWithEdges", func(t *testing.T) {
				nodes := []types.MeshNode{
					{
						MeshNode: &v1.MeshNode{
							Id:        "linked-node-a",
							PublicKey: mustGeneratePublicKey(t),
						},
					},
					{
						MeshNode: &v1.MeshNode{
							Id:        "linked-node-b",
							PublicKey: mustGeneratePublicKey(t),
						},
					},
				}
				for _, node := range nodes {
					if err := store.AddVertex(node.NodeID(), node, graph.VertexProperties{}); err != nil {
						t.Fatalf("AddVertex failed: %v", err)
					}
					// The vertex should eventually exist.
					var vertex types.MeshNode
					ok := Eventually[error](func() error {
						var err error
						vertex, _, err = store.Vertex(node.NodeID())
						return err
					}).ShouldNotError(time.Second*15, time.Second)
					if !ok {
						t.Fatalf("Vertex failed: %v", vertex)
					}
					if vertex.MeshNode == nil {
						t.Fatalf("Vertex is nil")
					}
					if !node.DeepEqual(vertex) {
						t.Errorf("Expected node %v, got %v", node, vertex)
					}
				}
				if err := store.AddEdge(nodes[0].NodeID(), nodes[1].NodeID(), graph.Edge[types.NodeID]{}); err != nil {
					t.Fatalf("AddEdge failed: %v", err)
				}
				// We should eventually be able to retrieve the edge
				var edge graph.Edge[types.NodeID]
				ok := Eventually[error](func() error {
					var err error
					edge, err = store.Edge(nodes[0].NodeID(), nodes[1].NodeID())
					return err
				}).ShouldNotError(time.Second*15, time.Second)
				if !ok {
					t.Fatalf("Edge failed: %v", edge)
				}
				// It should be empty
				if len(edge.Properties.Attributes) != 0 {
					t.Errorf("Expected empty edge, got %v", edge)
				}
				if edge.Properties.Weight != 0 {
					t.Errorf("Expected empty edge, got %v", edge)
				}
				// We should not be able to delete either node
				for _, node := range []string{"linked-node-a", "linked-node-b"} {
					err := store.RemoveVertex(types.NodeID(node))
					if err == nil {
						t.Errorf("RemoveVertex did not fail")
					}
					if !errors.Is(err, graph.ErrVertexHasEdges) {
						t.Errorf("Expected ErrVertexHasEdges, got %v", err)
					}
				}
				// Delete the edge
				if err := store.RemoveEdge(nodes[0].NodeID(), nodes[1].NodeID()); err != nil {
					t.Errorf("RemoveEdge failed: %v", err)
				}
				// We should now be able to delete both nodes
				for _, node := range []string{"linked-node-a", "linked-node-b"} {
					if err := store.RemoveVertex(types.NodeID(node)); err != nil {
						t.Errorf("RemoveVertex failed: %v", err)
					}
					// The node should eventually be gone
					var err error
					ok := Eventually[error](func() error {
						_, _, err = store.Vertex(types.NodeID(node))
						return err
					}).ShouldErrorWith(time.Second*15, time.Second, graph.ErrVertexNotFound)
					if !ok {
						t.Errorf("Expected ErrVertexNotFound, got %v", err)
					}
				}
			})
		})

		t.Run("AddAndRemoveEdges", func(t *testing.T) {
			nodes := []types.MeshNode{
				{
					MeshNode: &v1.MeshNode{
						Id:        "edge-node-a",
						PublicKey: mustGeneratePublicKey(t),
					},
				},
				{
					MeshNode: &v1.MeshNode{
						Id:        "edge-node-b",
						PublicKey: mustGeneratePublicKey(t),
					},
				},
			}
			for _, node := range nodes {
				if err := store.AddVertex(node.NodeID(), node, graph.VertexProperties{}); err != nil {
					t.Fatalf("AddVertex failed: %v", err)
				}
				// The vertex should eventually exist.
				var vertex types.MeshNode
				ok := Eventually[error](func() error {
					var err error
					vertex, _, err = store.Vertex(node.NodeID())
					return err
				}).ShouldNotError(time.Second*15, time.Second)
				if !ok {
					t.Fatalf("Vertex failed: %v", vertex)
				}
				if vertex.MeshNode == nil {
					t.Fatalf("Vertex is nil")
				}
				if !node.DeepEqual(vertex) {
					t.Errorf("Expected node %v, got %v", node, vertex)
				}
			}

			// Try to place an edge betwen two non-existing nodes
			err := store.AddEdge(types.NodeID("non-existing-a"), types.NodeID("non-existing-b"), graph.Edge[types.NodeID]{})
			if err == nil {
				t.Errorf("AddEdge did not fail")
			}
			if !errors.Is(err, graph.ErrVertexNotFound) {
				t.Errorf("Expected ErrVertexNotFound, got %v", err)
			}
			// Try to update a non-existing edge
			err = store.UpdateEdge(types.NodeID("non-existing-a"), types.NodeID("non-existing-b"), graph.Edge[types.NodeID]{})
			if err == nil {
				t.Errorf("UpdateEdge did not fail")
			}
			if !errors.Is(err, graph.ErrEdgeNotFound) {
				t.Errorf("Expected ErrEdgeNotFound, got %v", err)
			}

			// Place an empty edge between the two nodes
			if err := store.AddEdge(nodes[0].NodeID(), nodes[1].NodeID(), graph.Edge[types.NodeID]{}); err != nil {
				t.Fatalf("AddEdge failed: %v", err)
			}
			// We should eventually be able to retrieve the edge
			var edge graph.Edge[types.NodeID]
			ok := Eventually[error](func() error {
				var err error
				edge, err = store.Edge(nodes[0].NodeID(), nodes[1].NodeID())
				return err
			}).ShouldNotError(time.Second*15, time.Second)
			if !ok {
				t.Fatalf("Edge failed: %v", edge)
			}
			// It should be empty
			if len(edge.Properties.Attributes) != 0 {
				t.Errorf("Expected empty edge, got %v", edge)
			}
			if edge.Properties.Weight != 0 {
				t.Errorf("Expected empty edge, got %v", edge)
			}
			// Same goes for a list
			edges, err := store.ListEdges()
			if err != nil {
				t.Errorf("ListEdges failed: %v", err)
			}
			if len(edges) != 1 {
				t.Errorf("Expected 1 edge, got %d", len(edges))
			}
			edge = edges[0]
			if len(edge.Properties.Attributes) != 0 {
				t.Errorf("Expected empty edge, got %v", edge)
			}
			if edge.Properties.Weight != 0 {
				t.Errorf("Expected empty edge, got %v", edge)
			}

			// We should not be able to call AddEdge again
			err = store.AddEdge(nodes[0].NodeID(), nodes[1].NodeID(), graph.Edge[types.NodeID]{})
			if err == nil {
				t.Errorf("AddEdge did not fail")
			}
			if !errors.Is(err, graph.ErrEdgeAlreadyExists) {
				t.Errorf("Expected ErrEdgeExists, got %v", err)
			}

			// We _should_ be able to update the edge with a new weight and properties
			if err := store.UpdateEdge(nodes[0].NodeID(), nodes[1].NodeID(), graph.Edge[types.NodeID]{
				Properties: graph.EdgeProperties{
					Weight:     1,
					Attributes: map[string]string{"foo": "bar"},
				},
			}); err != nil {
				t.Errorf("UpdateEdge failed: %v", err)
			}
			// We should eventually get it back with our new weight
			var weight int
			ok = Eventually[int](func() int {
				var err error
				edge, err = store.Edge(nodes[0].NodeID(), nodes[1].NodeID())
				if err != nil {
					t.Errorf("Edge failed: %v", err)
					return 0
				}
				weight = edge.Properties.Weight
				return edge.Properties.Weight
			}).ShouldEqual(time.Second*15, time.Second, 1)
			if !ok {
				t.Errorf("Expected weight 1, got %d", weight)
			}
			// We should eventually get it back with our new properties
			var attributes map[string]string
			ok = Eventually[error](func() error {
				var err error
				edge, err = store.Edge(nodes[0].NodeID(), nodes[1].NodeID())
				if err != nil {
					t.Errorf("Edge failed: %v", err)
					return nil
				}
				attributes = edge.Properties.Attributes
				return err
			}).ShouldNotError(time.Second*15, time.Second)
			if !ok {
				t.Errorf("Expected attributes %v, got %v", map[string]string{"foo": "bar"}, attributes)
			}
			// The attributes should be correct
			if attributes["foo"] != "bar" {
				t.Errorf("Expected attributes %v, got %v", map[string]string{"foo": "bar"}, attributes)
			}
			// We should be able to delete the edge
			if err := store.RemoveEdge(nodes[0].NodeID(), nodes[1].NodeID()); err != nil {
				t.Errorf("RemoveEdge failed: %v", err)
			}
			// It should eventually be gone
			ok = Eventually[error](func() error {
				_, err = store.Edge(nodes[0].NodeID(), nodes[1].NodeID())
				return err
			}).ShouldErrorWith(time.Second*15, time.Second, graph.ErrEdgeNotFound)
			if !ok {
				t.Error("Edge did not return ErrEdgeNotFound, got:", err)
			}
			// Further deletes should not fail
			if err := store.RemoveEdge(nodes[0].NodeID(), nodes[1].NodeID()); err != nil {
				t.Errorf("RemoveEdge failed: %v", err)
			}
		})
	})
}
