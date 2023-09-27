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
	"bytes"
	"context"
	"errors"
	"testing"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	peergraph "github.com/webmeshproj/webmesh/pkg/meshdb/graph"
	"github.com/webmeshproj/webmesh/pkg/storage/backends/badgerdb"
)

func TestPeers(t *testing.T) {
	t.Parallel()

	t.Run("PutAndGetNode", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		p := setupPeersTest(t)

		tc := []struct {
			name    string
			invalid bool
			node    *v1.MeshNode
		}{
			{
				name: "invalid-node-id",
				node: &v1.MeshNode{
					Id: "invalid/node-id",
				},
				invalid: true,
			},
			{
				name: "valid-node",
				node: &v1.MeshNode{
					Id:        "node-id",
					PublicKey: mustGeneratePublicKey(t),
				},
			},
			{
				name: "valid-node-with-data",
				node: &v1.MeshNode{
					Id:                 "node-id",
					PublicKey:          mustGeneratePublicKey(t),
					PrimaryEndpoint:    "127.0.0.1",
					WireguardEndpoints: []string{"127.0.0.1:51820"},
					ZoneAwarenessId:    "zone-a",
					PrivateIpv4:        "172.16.0.1/32",
					PrivateIpv6:        "2001:db8::1/128",
				},
			},
		}

		for _, c := range tc {
			testCase := c
			t.Run(testCase.name, func(t *testing.T) {
				t.Parallel()
				err := p.Put(ctx, testCase.node)
				if err != nil && !testCase.invalid {
					t.Fatal(err)
				}
				if err == nil && testCase.invalid {
					t.Fatal("expected error")
				}
				if testCase.invalid {
					return
				}
				// Make sure the peer was actually stored
				node, err := p.Get(ctx, testCase.node.GetId())
				if err != nil {
					t.Fatal(err)
				}
				// The joined at field should be set
				if node.JoinedAt == nil {
					t.Fatal("joined at not set")
				} else if node.JoinedAt.AsTime().IsZero() {
					t.Fatal("joined at not set")
				}
				if !MeshNodesEqual(node.MeshNode, testCase.node) {
					t.Fatal("nodes not equal")
				}
			})
		}

		t.Run("NonExistingNode", func(t *testing.T) {
			t.Parallel()
			_, err := p.Get(ctx, "non-exist-node")
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, ErrNodeNotFound) {
				t.Fatal("expected node not found error")
			}
		})

		t.Run("DedupWireguardEndpoints", func(t *testing.T) {
			t.Parallel()
			node := &v1.MeshNode{
				Id:                 "node-id",
				PublicKey:          mustGeneratePublicKey(t),
				PrimaryEndpoint:    "127.0.0.1",
				WireguardEndpoints: []string{"127.0.0.1:51820", "127.0.0.2:51820", "127.0.0.1:51820"},
				ZoneAwarenessId:    "zone-a",
				PrivateIpv4:        "172.16.0.1/32",
				PrivateIpv6:        "2001:db8::1/128",
			}
			err := p.Put(ctx, node)
			if err != nil {
				t.Fatal(err)
			}
			// Make sure the peer was actually stored
			got, err := p.Get(ctx, node.GetId())
			if err != nil {
				t.Fatal(err)
			}
			if len(got.WireguardEndpoints) != 2 {
				t.Fatal("wireguard endpoints not deduped")
			}
			// Make sure the endpoints were deduped correctly
			for _, endpoint := range []string{"127.0.0.1:51820", "127.0.0.2:51820"} {
				found := false
				for _, gotEndpoint := range got.WireguardEndpoints {
					if endpoint == gotEndpoint {
						found = true
						break
					}
				}
				if !found {
					t.Fatal("endpoint not found")
				}
			}
		})
	})

	t.Run("GetNodeByPubKey", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		p := setupPeersTest(t)
		key := mustGeneratePublicKey(t)
		raw, err := crypto.DecodePublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		node := &v1.MeshNode{
			Id:                 "node-id",
			PublicKey:          key,
			PrimaryEndpoint:    "127.0.0.1",
			WireguardEndpoints: []string{"127.0.0.1:51820"},
			ZoneAwarenessId:    "zone-a",
			PrivateIpv4:        "172.16.0.1/32",
			PrivateIpv6:        "2001:db8::1/128",
		}
		err = p.Put(ctx, node)
		if err != nil {
			t.Fatal(err)
		}
		// Make sure the peer was actually stored
		got, err := p.Get(ctx, node.GetId())
		if err != nil {
			t.Fatal(err)
		}
		if !MeshNodesEqual(got.MeshNode, node) {
			t.Fatal("nodes not equal")
		}
		// Make sure we can get the node by public key
		got, err = p.GetByPubKey(ctx, raw)
		if err != nil {
			t.Fatal(err)
		}
		if !MeshNodesEqual(got.MeshNode, node) {
			t.Fatal("nodes not equal")
		}
	})

	t.Run("DeleteNode", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		p := setupPeersTest(t)
		node := &v1.MeshNode{
			Id:                 "node-id",
			PublicKey:          mustGeneratePublicKey(t),
			PrimaryEndpoint:    "127.0.0.1",
			WireguardEndpoints: []string{"127.0.0.1:51820"},
			ZoneAwarenessId:    "zone-a",
			PrivateIpv4:        "172.16.0.1/32",
			PrivateIpv6:        "2001:db8::1/128",
		}
		err := p.Put(ctx, node)
		if err != nil {
			t.Fatal(err)
		}
		// Make sure the peer was actually stored
		got, err := p.Get(ctx, node.GetId())
		if err != nil {
			t.Fatal(err)
		}
		if !MeshNodesEqual(got.MeshNode, node) {
			t.Fatal("nodes not equal")
		}
		// Delete the node
		err = p.Delete(ctx, node.GetId())
		if err != nil {
			t.Fatal(err)
		}
		// Make sure the node was actually deleted
		_, err = p.Get(ctx, node.GetId())
		if err == nil {
			t.Fatal("expected error")
		}
		if !errors.Is(err, ErrNodeNotFound) {
			t.Fatal("expected node not found error")
		}
		// Further calls to delete should not fail.
		err = p.Delete(ctx, node.GetId())
		if err != nil {
			t.Fatal(err)
		}

		t.Run("WithEdges", func(t *testing.T) {
			t.Parallel()
			nodeA := &v1.MeshNode{
				Id:                 "node-a",
				PublicKey:          mustGeneratePublicKey(t),
				PrimaryEndpoint:    "127.0.0.1",
				WireguardEndpoints: []string{"127.0.0.1:51820"},
				ZoneAwarenessId:    "zone-a",
				PrivateIpv4:        "172.16.0.1/32",
				PrivateIpv6:        "2001:db8::1/128",
			}
			nodeB := &v1.MeshNode{
				Id:                 "node-b",
				PublicKey:          mustGeneratePublicKey(t),
				PrimaryEndpoint:    "127.0.0.1",
				WireguardEndpoints: []string{"127.0.0.1:51820"},
				ZoneAwarenessId:    "zone-a",
				PrivateIpv4:        "172.16.0.2/32",
				PrivateIpv6:        "2001:db8::2/128",
			}
			err := p.Put(ctx, nodeA)
			if err != nil {
				t.Fatal(err)
			}
			err = p.Put(ctx, nodeB)
			if err != nil {
				t.Fatal(err)
			}
			// Add an edge between the two nodes
			err = p.PutEdge(ctx, &v1.MeshEdge{
				Source: nodeA.GetId(),
				Target: nodeB.GetId(),
			})
			if err != nil {
				t.Fatal(err)
			}
			// Delete nodeA
			err = p.Delete(ctx, nodeA.GetId())
			if err != nil {
				t.Fatal(err)
			}
			// The edge should be gone
			_, err = p.Graph().Edge(peergraph.NodeID(nodeA.GetId()), peergraph.NodeID(nodeB.GetId()))
			if err == nil {
				t.Fatal("expected error")
			}
		})
	})

	t.Run("ListNodes", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		p := setupPeersTest(t)
		nodes := []*v1.MeshNode{
			{
				Id:                 "node-a",
				PublicKey:          mustGeneratePublicKey(t),
				PrimaryEndpoint:    "127.0.0.1",
				WireguardEndpoints: []string{"127.0.0.1:51820"},
				ZoneAwarenessId:    "zone-a",
				PrivateIpv4:        "172.16.0.1/32",
				PrivateIpv6:        "2001:db8::1/128",
			},
			{
				Id:                 "node-b",
				PublicKey:          mustGeneratePublicKey(t),
				PrimaryEndpoint:    "127.0.0.1",
				WireguardEndpoints: []string{"127.0.0.1:51820"},
				ZoneAwarenessId:    "zone-a",
				PrivateIpv4:        "172.16.0.2/32",
				PrivateIpv6:        "2001:db8::2/128",
			},
		}
		for _, node := range nodes {
			err := p.Put(ctx, node)
			if err != nil {
				t.Fatal(err)
			}
		}
		got, err := p.List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(nodes) {
			t.Fatal("nodes not equal")
		}
		for _, node := range nodes {
			found := false
			for _, gotNode := range got {
				if MeshNodesEqual(gotNode.MeshNode, node) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("node %q not found", node.GetId())
			}
		}
	})

	t.Run("ListNodeIDs", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		p := setupPeersTest(t)
		nodes := []*v1.MeshNode{
			{
				Id:                 "node-a",
				PublicKey:          mustGeneratePublicKey(t),
				PrimaryEndpoint:    "127.0.0.1",
				WireguardEndpoints: []string{"127.0.0.1:51820"},
				ZoneAwarenessId:    "zone-a",
				PrivateIpv4:        "172.16.0.1/32",
				PrivateIpv6:        "2001:db8::1/128",
			},
			{
				Id:                 "node-b",
				PublicKey:          mustGeneratePublicKey(t),
				PrimaryEndpoint:    "127.0.0.1",
				WireguardEndpoints: []string{"127.0.0.1:51820"},
				ZoneAwarenessId:    "zone-a",
				PrivateIpv4:        "172.16.0.2/32",
				PrivateIpv6:        "2001:db8::2/128",
			},
		}
		for _, node := range nodes {
			err := p.Put(ctx, node)
			if err != nil {
				t.Fatal(err)
			}
		}
		got, err := p.ListIDs(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(nodes) {
			t.Fatal("nodes not equal")
		}
		for _, node := range nodes {
			found := false
			for _, gotNode := range got {
				if gotNode == node.GetId() {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("node %q not found", node.GetId())
			}
		}
	})

	t.Run("ListPublicNodes", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		p := setupPeersTest(t)
		nodes := []*v1.MeshNode{
			{
				Id:                 "node-a-public",
				PublicKey:          mustGeneratePublicKey(t),
				PrimaryEndpoint:    "8.8.8.8",
				WireguardEndpoints: []string{"8.8.8.8:51820"},
				ZoneAwarenessId:    "zone-a",
			},
			{
				Id:              "node-b-private",
				PublicKey:       mustGeneratePublicKey(t),
				ZoneAwarenessId: "zone-a",
			},
		}
		for _, node := range nodes {
			err := p.Put(ctx, node)
			if err != nil {
				t.Fatal(err)
			}
		}
		got, err := p.ListPublicNodes(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatal("expected only one public node")
		}
		if !MeshNodesEqual(got[0].MeshNode, nodes[0]) {
			t.Fatal("nodes not equal")
		}
	})

	t.Run("ListByZoneID", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		p := setupPeersTest(t)
		nodes := []*v1.MeshNode{
			{
				Id:              "node-a-zone-a",
				PublicKey:       mustGeneratePublicKey(t),
				ZoneAwarenessId: "zone-a",
			},
			{
				Id:              "node-b-zone-a",
				PublicKey:       mustGeneratePublicKey(t),
				ZoneAwarenessId: "zone-a",
			},
			{
				Id:              "node-a-zone-b",
				PublicKey:       mustGeneratePublicKey(t),
				ZoneAwarenessId: "zone-b",
			},
			{
				Id:              "node-b-zone-b",
				PublicKey:       mustGeneratePublicKey(t),
				ZoneAwarenessId: "zone-b",
			},
		}
		for _, node := range nodes {
			err := p.Put(ctx, node)
			if err != nil {
				t.Fatal(err)
			}
		}
		got, err := p.ListByZoneID(ctx, "zone-a")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatal("expected two nodes got", len(got))
		}
		for _, node := range nodes {
			if node.GetZoneAwarenessId() != "zone-a" {
				continue
			}
			found := false
			for _, gotNode := range got {
				if MeshNodesEqual(gotNode.MeshNode, node) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("node %q not found", node.GetId())
			}
		}
		got, err = p.ListByZoneID(ctx, "zone-b")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatal("expected two nodes, got", len(got))
		}
		for _, node := range nodes {
			if node.GetZoneAwarenessId() != "zone-b" {
				continue
			}
			found := false
			for _, gotNode := range got {
				if MeshNodesEqual(gotNode.MeshNode, node) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("node %q not found", node.GetId())
			}
		}
	})

	t.Run("ListByFeature", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		p := setupPeersTest(t)
		nodes := []*v1.MeshNode{
			{
				Id:        "node-a",
				PublicKey: mustGeneratePublicKey(t),
				Features: []*v1.FeaturePort{
					{
						Feature: v1.Feature_ADMIN_API,
						Port:    8080,
					},
				},
			},
			{
				Id:        "node-b",
				PublicKey: mustGeneratePublicKey(t),
				Features: []*v1.FeaturePort{
					{
						Feature: v1.Feature_ADMIN_API,
						Port:    8080,
					},
				},
			},
			{
				Id:        "node-c",
				PublicKey: mustGeneratePublicKey(t),
				Features: []*v1.FeaturePort{
					{
						Feature: v1.Feature_ICE_NEGOTIATION,
						Port:    8080,
					},
				},
			},
			{
				Id:        "node-d",
				PublicKey: mustGeneratePublicKey(t),
				Features: []*v1.FeaturePort{
					{
						Feature: v1.Feature_MESH_DNS,
						Port:    8080,
					},
				},
			},
		}
		for _, node := range nodes {
			err := p.Put(ctx, node)
			if err != nil {
				t.Fatal(err)
			}
		}
		// Two nodes for admin API, one for ICE negotiation, one for mesh DNS
		got, err := p.ListByFeature(ctx, v1.Feature_ADMIN_API)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatal("expected two nodes, got", len(got))
		}
		for _, node := range nodes {
			if !(peergraph.MeshNode{MeshNode: node}).HasFeature(v1.Feature_ADMIN_API) {
				continue
			}
			found := false
			for _, gotNode := range got {
				if MeshNodesEqual(gotNode.MeshNode, node) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("node %q not found", node.GetId())
			}
		}
		got, err = p.ListByFeature(ctx, v1.Feature_ICE_NEGOTIATION)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatal("expected one node, got", len(got))
		}
		for _, node := range nodes {
			if !(peergraph.MeshNode{MeshNode: node}).HasFeature(v1.Feature_ICE_NEGOTIATION) {
				continue
			}
			found := false
			for _, gotNode := range got {
				if MeshNodesEqual(gotNode.MeshNode, node) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("node %q not found", node.GetId())
			}
		}
		got, err = p.ListByFeature(ctx, v1.Feature_MESH_DNS)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatal("expected one node, got", len(got))
		}
		for _, node := range nodes {
			if !(peergraph.MeshNode{MeshNode: node}).HasFeature(v1.Feature_MESH_DNS) {
				continue
			}
			found := false
			for _, gotNode := range got {
				if MeshNodesEqual(gotNode.MeshNode, node) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("node %q not found", node.GetId())
			}
		}
	})

	t.Run("PutAndRemoveEdge", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		p := setupPeersTest(t)
		nodes := []*v1.MeshNode{
			{
				Id:              "node-a",
				PublicKey:       mustGeneratePublicKey(t),
				ZoneAwarenessId: "zone-a",
			},
			{
				Id:        "node-b",
				PublicKey: mustGeneratePublicKey(t),
			},
		}
		for _, node := range nodes {
			err := p.Put(ctx, node)
			if err != nil {
				t.Fatal(err)
			}
		}
		// Add an edge between the two nodes
		err := p.PutEdge(ctx, &v1.MeshEdge{
			Source: nodes[0].GetId(),
			Target: nodes[1].GetId(),
		})
		if err != nil {
			t.Fatal(err)
		}
		// Make sure the edge was actually stored
		edge, err := p.Graph().Edge(peergraph.NodeID(nodes[0].GetId()), peergraph.NodeID(nodes[1].GetId()))
		if err != nil {
			t.Fatal(err)
		}
		if !MeshNodesEqual(edge.Source.MeshNode, nodes[0]) {
			t.Fatal("source nodes not equal")
		}
		if !MeshNodesEqual(edge.Target.MeshNode, nodes[1]) {
			t.Fatal("target nodes not equal")
		}

		// Remove the edge
		err = p.RemoveEdge(ctx, nodes[0].GetId(), nodes[1].GetId())
		if err != nil {
			t.Fatal(err)
		}
		// Make sure the edge was actually removed
		_, err = p.Graph().Edge(peergraph.NodeID(nodes[0].GetId()), peergraph.NodeID(nodes[1].GetId()))
		if err == nil {
			t.Fatal("expected error")
		}
		// Further calls to delete edge should not error
		err = p.RemoveEdge(ctx, nodes[0].GetId(), nodes[1].GetId())
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("DrawDOTGraph", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		p := setupPeersTest(t)
		nodes := []*v1.MeshNode{
			{
				Id:              "node-a",
				PublicKey:       mustGeneratePublicKey(t),
				ZoneAwarenessId: "zone-a",
			},
			{
				Id:        "node-b",
				PublicKey: mustGeneratePublicKey(t),
			},
		}
		for _, node := range nodes {
			err := p.Put(ctx, node)
			if err != nil {
				t.Fatal(err)
			}
		}
		// Add an edge between the two nodes
		err := p.PutEdge(ctx, &v1.MeshEdge{
			Source: nodes[0].GetId(),
			Target: nodes[1].GetId(),
		})
		if err != nil {
			t.Fatal(err)
		}

		// Draw the dot graph
		var buf bytes.Buffer
		err = p.DrawDOTGraph(ctx, &buf)
		if err != nil {
			t.Fatal(err)
		}
		t.Log("Computed graph:", buf.String())
		// Scan each line and make sure it's in the expected graph
		expected := `strict graph {


			"node-a" [  weight=0 ];

			"node-a" -- "node-b" [  weight=0 ];

			"node-b" [  weight=0 ];

			"node-b" -- "node-a" [  weight=0 ];

		}
		`
		expectedLines := bytes.Split([]byte(expected), []byte("\n"))
		for i, line := range bytes.Split(buf.Bytes(), []byte("\n")) {
			line = bytes.TrimSpace(line)
			expectedLine := bytes.TrimSpace(expectedLines[i])
			t.Log("Comparing line:", "'"+string(line)+"'", "to expected:", "'"+string(expectedLine)+"'")
			if !bytes.Equal(expectedLine, line) {
				t.Fatalf("line %d not found in expected graph", i)
			}
		}
	})
}

func setupPeersTest(t *testing.T) *peerDB {
	t.Helper()
	db, err := badgerdb.NewInMemory(badgerdb.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
	})
	st := New(db)
	return st.(*peerDB)
}

func mustGeneratePublicKey(t *testing.T) string {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := key.PublicKey().Encode()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
