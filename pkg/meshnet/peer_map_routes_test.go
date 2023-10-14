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
	"reflect"
	"sort"
	"testing"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

func TestWireGuardPeersWithRoutes(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name       string
		peers      []types.MeshNode
		routes     []types.Route
		edges      map[string][]string            // peerID -> []peerID
		wantRoutes map[string]map[string][]string // peerID -> peerID -> []routes
	}{
		{
			name: "SinglePeerSingleRoute",
			peers: []types.MeshNode{
				{MeshNode: &v1.MeshNode{
					Id:          "node-a",
					PrivateIPv4: "172.16.0.1/32",
					PrivateIPv6: "2001:db8::1/128",
				}},
				{MeshNode: &v1.MeshNode{
					Id:          "node-b",
					PrivateIPv4: "172.16.0.2/32",
					PrivateIPv6: "2001:db8::2/128",
				}},
			},
			routes: []types.Route{
				{Route: &v1.Route{
					Name:             "node-a-full-tunnel",
					Node:             "node-a",
					DestinationCIDRs: []string{"0.0.0.0/0", "::/0"},
				}},
			},
			edges: map[string][]string{
				"node-a": {"node-b"},
				"node-b": {"node-a"},
			},
			wantRoutes: map[string]map[string][]string{
				"node-a": {
					"node-b": {},
				},
				"node-b": {
					"node-a": {"0.0.0.0/0", "::/0"},
				},
			},
		},
		{
			name: "SiteToSiteFullTunnel",
			peers: []types.MeshNode{
				{MeshNode: &v1.MeshNode{
					Id:          "site-a-leader",
					PrivateIPv4: "172.16.0.1/32",
					PrivateIPv6: "2001:db8::1/128",
				}},
				{MeshNode: &v1.MeshNode{
					Id:          "site-b-leader",
					PrivateIPv4: "172.16.0.2/32",
					PrivateIPv6: "2001:db8::2/128",
				}},
				{MeshNode: &v1.MeshNode{
					Id:          "site-c-leader",
					PrivateIPv4: "172.16.0.3/32",
					PrivateIPv6: "2001:db8::3/128",
				}},
				{MeshNode: &v1.MeshNode{
					Id:          "site-a-follower",
					PrivateIPv4: "172.16.0.4/32",
					PrivateIPv6: "2001:db8::4/128",
				}},
				{MeshNode: &v1.MeshNode{
					Id:          "site-b-follower",
					PrivateIPv4: "172.16.0.5/32",
					PrivateIPv6: "2001:db8::5/128",
				}},
				{MeshNode: &v1.MeshNode{
					Id:          "site-c-follower",
					PrivateIPv4: "172.16.0.6/32",
					PrivateIPv6: "2001:db8::6/128",
				}},
			},
			routes: []types.Route{
				{Route: &v1.Route{
					Name:             "site-a-full-tunnel",
					Node:             "site-a-leader",
					DestinationCIDRs: []string{"0.0.0.0/0", "::/0"},
				}},
				{Route: &v1.Route{
					Name:             "site-b-full-tunnel",
					Node:             "site-b-leader",
					DestinationCIDRs: []string{"0.0.0.0/0", "::/0"},
				}},
				{Route: &v1.Route{
					Name:             "site-c-full-tunnel",
					Node:             "site-c-leader",
					DestinationCIDRs: []string{"0.0.0.0/0", "::/0"},
				}},
			},
			edges: map[string][]string{
				"site-a-leader": {"site-b-leader", "site-c-leader", "site-a-follower"},
				"site-b-leader": {"site-a-leader", "site-c-leader", "site-b-follower"},
				"site-c-leader": {"site-a-leader", "site-b-leader", "site-c-follower"},
			},
			wantRoutes: map[string]map[string][]string{
				"site-a-leader": {
					"site-b-leader":   {},
					"site-c-leader":   {},
					"site-a-follower": {},
				},
				"site-b-leader": {
					"site-a-leader":   {},
					"site-c-leader":   {},
					"site-b-follower": {},
				},
				"site-c-leader": {
					"site-a-leader":   {},
					"site-b-leader":   {},
					"site-c-follower": {},
				},
				"site-a-follower": {
					"site-a-leader": {"0.0.0.0/0", "::/0"},
				},
				"site-b-follower": {
					"site-b-leader": {"0.0.0.0/0", "::/0"},
				},
				"site-c-follower": {
					"site-c-leader": {"0.0.0.0/0", "::/0"},
				},
			},
		},
	}

	for _, testcase := range tt {
		tc := testcase
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			db := meshdb.NewTestDB()
			defer db.Close()
			// Set the network state
			err := db.MeshState().SetMeshState(ctx, types.NetworkState{
				NetworkState: &v1.NetworkState{
					NetworkV4: "172.16.0.0/12",
					NetworkV6: "2001:db8::/64",
					Domain:    "example.com",
				},
			})
			if err != nil {
				t.Fatalf("set network state: %v", err)
			}
			for _, peer := range tc.peers {
				peer.PublicKey = mustGeneratePublicKey(t)
				if err := db.Peers().Put(ctx, peer); err != nil {
					t.Fatal(err)
				}
			}
			for peerID, edges := range tc.edges {
				for _, edge := range edges {
					err := db.Peers().PutEdge(ctx, types.MeshEdge{MeshEdge: &v1.MeshEdge{
						Source: peerID,
						Target: edge,
					}})
					if err != nil {
						t.Fatalf("put edge from %q to %q: %v", peerID, edge, err)
					}
				}
			}
			for _, route := range tc.routes {
				if err := db.Networking().PutRoute(ctx, route); err != nil {
					t.Fatal(err)
				}
			}
			// Create an allow-all ACL
			err = db.Networking().PutNetworkACL(ctx, types.NetworkACL{
				NetworkACL: &v1.NetworkACL{
					Name:             "allow-all",
					Priority:         0,
					Action:           v1.ACLAction_ACTION_ACCEPT,
					SourceNodes:      []string{"*"},
					DestinationNodes: []string{"*"},
					SourceCIDRs:      []string{"*"},
					DestinationCIDRs: []string{"*"},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for peer, want := range tc.wantRoutes {
				peers, err := WireGuardPeersFor(ctx, db, types.NodeID(peer))
				if err != nil {
					t.Fatalf("get peers for %q: %v", peer, err)
				}
				// Make sure strings are sorted for comparison.
				for _, ips := range want {
					sort.Strings(ips)
				}
				got := make(map[string][]string)
				for _, p := range peers {
					sort.Strings(p.AllowedRoutes)
					got[p.Node.GetId()] = p.AllowedRoutes
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("peer: %s got routes %v, wanted routes %v", peer, got, want)
				}
			}
		})
	}
}
