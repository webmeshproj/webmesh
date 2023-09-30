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

package meshnet

import (
	"context"
	"errors"
	"testing"

	"github.com/dominikbraun/graph"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

func TestFilteredGraph(t *testing.T) {
	t.Parallel()

	t.Run("NoNetworkACLs", func(t *testing.T) {
		t.Parallel()

		db := setupGraphTest(t, graphSetup{
			nodes: []types.MeshNode{
				{
					MeshNode: &v1.MeshNode{
						Id:          "node-a",
						PublicKey:   generateEncodedKey(t),
						PrivateIpv4: "172.16.0.1/32",
						PrivateIpv6: "fe80::1/128",
					},
				},
				{
					MeshNode: &v1.MeshNode{
						Id:          "node-b",
						PublicKey:   generateEncodedKey(t),
						PrivateIpv4: "172.16.0.2/32",
						PrivateIpv6: "fe80::2/128",
					},
				},
			},
			edges: []types.MeshEdge{
				{
					MeshEdge: &v1.MeshEdge{
						Source: "node-a",
						Target: "node-b",
					},
				},
				{
					MeshEdge: &v1.MeshEdge{
						Source: "node-b",
						Target: "node-a",
					},
				},
			},
		})

		filteredA, err := FilterGraph(context.Background(), db, "node-a")
		if err != nil {
			t.Fatalf("filter graph: %v", err)
		}
		filteredB, err := FilterGraph(context.Background(), db, "node-b")
		if err != nil {
			t.Fatalf("filter graph: %v", err)
		}

		// Both maps should be empty
		if len(filteredA) != 0 || len(filteredB) != 0 {
			t.Fatalf("filtered graph should be empty")
		}
	})

	t.Run("DenyAll", func(t *testing.T) {
		t.Parallel()

		db := setupGraphTest(t, graphSetup{
			nodes: []types.MeshNode{
				{
					MeshNode: &v1.MeshNode{
						Id:          "node-a",
						PublicKey:   generateEncodedKey(t),
						PrivateIpv4: "172.16.0.1/32",
						PrivateIpv6: "fe80::1/128",
					},
				},
				{
					MeshNode: &v1.MeshNode{
						Id:          "node-b",
						PublicKey:   generateEncodedKey(t),
						PrivateIpv4: "172.16.0.2/32",
						PrivateIpv6: "fe80::2/128",
					},
				},
			},
			edges: []types.MeshEdge{
				{
					MeshEdge: &v1.MeshEdge{
						Source: "node-a",
						Target: "node-b",
					},
				},
				{
					MeshEdge: &v1.MeshEdge{
						Source: "node-b",
						Target: "node-a",
					},
				},
			},
			acls: []*v1.NetworkACL{
				{
					Name:             "deny-all",
					Action:           v1.ACLAction_ACTION_DENY,
					SourceNodes:      []string{"*"},
					DestinationNodes: []string{"*"},
					SourceCidrs:      []string{"*"},
					DestinationCidrs: []string{"*"},
				},
			},
		})

		filteredA, err := FilterGraph(context.Background(), db, "node-a")
		if err != nil {
			t.Fatalf("filter graph: %v", err)
		}
		filteredB, err := FilterGraph(context.Background(), db, "node-b")
		if err != nil {
			t.Fatalf("filter graph: %v", err)
		}

		// Each map should be a single entry, with the node itself and no edges
		if len(filteredA) != 1 || len(filteredB) != 1 {
			t.Fatalf("filtered graph should contain only one node")
		}

		aedges := filteredA["node-a"]
		if len(aedges) != 0 {
			t.Fatalf("filtered graph should contain no edges")
		}

		bedges := filteredB["node-b"]
		if len(bedges) != 0 {
			t.Fatalf("filtered graph should contain no edges")
		}
	})

	t.Run("AllowAll", func(t *testing.T) {
		t.Parallel()

		db := setupGraphTest(t, graphSetup{
			nodes: []types.MeshNode{
				{
					MeshNode: &v1.MeshNode{
						Id:          "node-a",
						PublicKey:   generateEncodedKey(t),
						PrivateIpv4: "172.16.0.1/32",
						PrivateIpv6: "fe80::1/128",
					},
				},
				{
					MeshNode: &v1.MeshNode{
						Id:          "node-b",
						PublicKey:   generateEncodedKey(t),
						PrivateIpv4: "172.16.0.2/32",
						PrivateIpv6: "fe80::2/128",
					},
				},
			},
			edges: []types.MeshEdge{
				{
					MeshEdge: &v1.MeshEdge{
						Source: "node-a",
						Target: "node-b",
					},
				},
				{
					MeshEdge: &v1.MeshEdge{
						Source: "node-b",
						Target: "node-a",
					},
				},
			},
			acls: []*v1.NetworkACL{
				{
					Name:             "allow-all",
					Action:           v1.ACLAction_ACTION_ACCEPT,
					SourceNodes:      []string{"*"},
					DestinationNodes: []string{"*"},
					SourceCidrs:      []string{"*"},
					DestinationCidrs: []string{"*"},
				},
			},
		})

		filteredA, err := FilterGraph(context.Background(), db, "node-a")
		if err != nil {
			t.Fatalf("filter graph: %v", err)
		}
		filteredB, err := FilterGraph(context.Background(), db, "node-b")
		if err != nil {
			t.Fatalf("filter graph: %v", err)
		}

		// Each map should contain both nodes
		if len(filteredA) != 2 || len(filteredB) != 2 {
			t.Fatalf("filtered graphs should contain both nodes")
		}

		// Each graph should have one edge
		aedges := filteredA["node-a"]
		if len(aedges) != 1 {
			t.Fatalf("filtered graph should contain one edge, got: %d", len(aedges))
		}

		bedges := filteredB["node-b"]
		if len(bedges) != 1 {
			t.Fatalf("filtered graph should contain one edge, got: %d", len(bedges))
		}

		// The graphs should be equal
		if !filteredA.DeepEqual(filteredB) {
			t.Fatalf("filtered graphs should be equal")
		}
	})
}

type graphSetup struct {
	acls   []*v1.NetworkACL
	nodes  []types.MeshNode
	edges  []types.MeshEdge
	routes []*v1.Route
}

func setupGraphTest(t *testing.T, opts graphSetup) storage.MeshDB {
	t.Helper()
	db := meshdb.NewTestDB()
	nw := db.Networking()
	for _, acl := range opts.acls {
		if err := nw.PutNetworkACL(context.Background(), types.NetworkACL{NetworkACL: acl}); err != nil {
			t.Fatalf("put network ACL: %v", err)
		}
	}
	for _, route := range opts.routes {
		if err := nw.PutRoute(context.Background(), types.Route{Route: route}); err != nil {
			t.Fatalf("put route: %v", err)
		}
	}
	pgraph := db.PeerGraph()
	for _, node := range opts.nodes {
		if err := pgraph.AddVertex(node); err != nil {
			t.Fatalf("add vertex: %v", err)
		}
	}
	for _, edge := range opts.edges {
		if err := pgraph.AddEdge(
			types.NodeID(edge.Source), types.NodeID(edge.Target),
			graph.EdgeAttributes(edge.Attributes),
			graph.EdgeWeight(int(edge.Weight)),
		); err != nil && !errors.Is(err, graph.ErrEdgeAlreadyExists) {
			t.Fatalf("add edge: %v", err)
		}
	}
	return db
}

func generateEncodedKey(t *testing.T) string {
	t.Helper()
	key := crypto.MustGenerateKey()
	encoded, err := key.PublicKey().Encode()
	if err != nil {
		t.Fatalf("encode key: %v", err)
	}
	return encoded
}
