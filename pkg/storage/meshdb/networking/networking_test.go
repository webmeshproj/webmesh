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

package networking

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/backends/badgerdb"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

func TestNetworkACLs(t *testing.T) {
	t.Parallel()

	t.Run("GetPutACL", func(t *testing.T) {
		t.Parallel()
		nw := setupTest(t)
		t.Run("ValidACLs", func(t *testing.T) {
			t.Parallel()
			tc := []struct {
				name string
				acl  *types.NetworkACL
			}{
				{
					name: "wildcard-acl",
					acl: &types.NetworkACL{
						NetworkACL: &v1.NetworkACL{
							Name:             "wildcard-acl",
							Priority:         0,
							Action:           v1.ACLAction_ACTION_ACCEPT,
							SourceNodes:      []string{"*"},
							DestinationNodes: []string{"*"},
							SourceCidrs:      []string{"*"},
							DestinationCidrs: []string{"*"},
						},
					},
				},
				{
					name: "nodes-acl",
					acl: &types.NetworkACL{
						NetworkACL: &v1.NetworkACL{
							Name:             "wildcard-acl",
							Priority:         0,
							Action:           v1.ACLAction_ACTION_ACCEPT,
							SourceNodes:      []string{"node1", "node2"},
							DestinationNodes: []string{"node1", "node2"},
							SourceCidrs:      []string{"*"},
							DestinationCidrs: []string{"*"},
						},
					},
				},
				{
					name: "v4cidrs-acl",
					acl: &types.NetworkACL{
						NetworkACL: &v1.NetworkACL{
							Name:             "v4cidrs-acl",
							Priority:         0,
							Action:           v1.ACLAction_ACTION_ACCEPT,
							SourceNodes:      []string{"*"},
							DestinationNodes: []string{"*"},
							SourceCidrs:      []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
							DestinationCidrs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
						},
					},
				},
				{
					name: "v6cidrs-acl",
					acl: &types.NetworkACL{
						NetworkACL: &v1.NetworkACL{
							Name:             "v6cidrs-acl",
							Priority:         0,
							Action:           v1.ACLAction_ACTION_ACCEPT,
							SourceNodes:      []string{"*"},
							DestinationNodes: []string{"*"},
							SourceCidrs:      []string{"2001:db8::/32", "2001:db8:ffff::/48"},
							DestinationCidrs: []string{"2001:db8::/32", "2001:db8:ffff::/48"},
						},
					},
				},
			}
			for _, tt := range tc {
				testCase := tt
				t.Run(tt.name, func(t *testing.T) {
					t.Parallel()
					err := nw.PutNetworkACL(context.Background(), testCase.acl.NetworkACL)
					if err != nil {
						t.Fatalf("put network acl: %v", err)
					}
					got, err := nw.GetNetworkACL(context.Background(), testCase.acl.GetName())
					if err != nil {
						t.Fatalf("get network acl: %v", err)
					}
					if !testCase.acl.Equals(got) {
						t.Fatalf("expected %v, got %v", testCase.acl, got)
					}
				})
			}
		})

		t.Run("InvalidACLs", func(t *testing.T) {
			t.Parallel()
			nw := setupTest(t)
			tc := []struct {
				name string
				acl  *types.NetworkACL
			}{
				{
					name: "empty-name",
					acl: &types.NetworkACL{
						NetworkACL: &v1.NetworkACL{
							Name:             "",
							Priority:         0,
							Action:           v1.ACLAction_ACTION_ACCEPT,
							SourceNodes:      []string{"*"},
							DestinationNodes: []string{"*"},
							SourceCidrs:      []string{"*"},
							DestinationCidrs: []string{"*"},
						},
					},
				},
				{
					name: "invalid-name",
					acl: &types.NetworkACL{
						NetworkACL: &v1.NetworkACL{
							Name:             "invalid/name",
							Priority:         0,
							Action:           v1.ACLAction_ACTION_ACCEPT,
							SourceNodes:      []string{"*"},
							DestinationNodes: []string{"*"},
							SourceCidrs:      []string{"*"},
							DestinationCidrs: []string{"*"},
						},
					},
				},
				{
					name: "invalid-action",
					acl: &types.NetworkACL{
						NetworkACL: &v1.NetworkACL{
							Name:             "network-acl",
							Priority:         0,
							Action:           -1,
							SourceNodes:      []string{"*"},
							DestinationNodes: []string{"*"},
							SourceCidrs:      []string{"*"},
							DestinationCidrs: []string{"*"},
						},
					},
				},
				{
					name: "invalid-src-node-ids",
					acl: &types.NetworkACL{
						NetworkACL: &v1.NetworkACL{
							Name:             "network-acl",
							Priority:         0,
							Action:           v1.ACLAction_ACTION_ACCEPT,
							SourceNodes:      []string{"invalid/node1", "invalid/node2"},
							DestinationNodes: []string{"*"},
							SourceCidrs:      []string{"*"},
							DestinationCidrs: []string{"*"},
						},
					},
				},
				{
					name: "invalid-dst-node-ids",
					acl: &types.NetworkACL{
						NetworkACL: &v1.NetworkACL{
							Name:             "network-acl",
							Priority:         0,
							Action:           v1.ACLAction_ACTION_ACCEPT,
							SourceNodes:      []string{"*"},
							DestinationNodes: []string{"invalid/node1", "invalid/node2"},
							SourceCidrs:      []string{"*"},
							DestinationCidrs: []string{"*"},
						},
					},
				},
				{
					name: "invalid-src-cidrs",
					acl: &types.NetworkACL{
						NetworkACL: &v1.NetworkACL{
							Name:             "network-acl",
							Priority:         0,
							Action:           v1.ACLAction_ACTION_ACCEPT,
							SourceNodes:      []string{"*"},
							DestinationNodes: []string{"*"},
							SourceCidrs:      []string{"invalid/cidr1", "invalid/cidr2"},
							DestinationCidrs: []string{"*"},
						},
					},
				},
				{
					name: "invalid-dst-cidrs",
					acl: &types.NetworkACL{
						NetworkACL: &v1.NetworkACL{
							Name:             "network-acl",
							Priority:         0,
							Action:           v1.ACLAction_ACTION_ACCEPT,
							SourceNodes:      []string{"*"},
							DestinationNodes: []string{"*"},
							SourceCidrs:      []string{"*"},
							DestinationCidrs: []string{"invalid/cidr1", "invalid/cidr2"},
						},
					},
				},
			}
			for _, tt := range tc {
				testCase := tt
				t.Run(tt.name, func(t *testing.T) {
					t.Parallel()
					err := nw.PutNetworkACL(context.Background(), testCase.acl.NetworkACL)
					if err == nil {
						t.Fatalf("expected error, got nil")
					}
					if !errors.Is(err, storage.ErrInvalidACL) {
						t.Errorf("expected %v, got %v", storage.ErrInvalidACL, err)
					}
				})
			}
		})
	})

	t.Run("DeleteACLs", func(t *testing.T) {
		t.Parallel()
		nw := setupTest(t)

		// Put a valid ACL, we should be able to delete it
		// and further calls to delete should not error.
		acl := &types.NetworkACL{
			NetworkACL: &v1.NetworkACL{
				Name:             "wildcard-acl",
				Priority:         0,
				Action:           v1.ACLAction_ACTION_ACCEPT,
				SourceNodes:      []string{"*"},
				DestinationNodes: []string{"*"},
				SourceCidrs:      []string{"*"},
				DestinationCidrs: []string{"*"},
			},
		}
		err := nw.PutNetworkACL(context.Background(), acl.NetworkACL)
		if err != nil {
			t.Fatalf("put network acl: %v", err)
		}
		err = nw.DeleteNetworkACL(context.Background(), acl.GetName())
		if err != nil {
			t.Fatalf("delete network acl: %v", err)
		}
		// The ACL should be gone
		_, err = nw.GetNetworkACL(context.Background(), acl.GetName())
		if err == nil {
			t.Fatalf("expected error, got nil")
		} else if !errors.Is(err, storage.ErrACLNotFound) {
			t.Fatalf("expected %v, got %v", storage.ErrACLNotFound, err)
		}
		// Further calls to delete should not error
		err = nw.DeleteNetworkACL(context.Background(), acl.GetName())
		if err != nil {
			t.Fatalf("delete network acl: %v", err)
		}
	})

	t.Run("ListACLs", func(t *testing.T) {
		t.Parallel()

		// Put a few ACLs
		nw := setupTest(t)
		acls := []types.NetworkACL{
			{
				NetworkACL: &v1.NetworkACL{
					Name:             "acl1",
					Priority:         0,
					Action:           v1.ACLAction_ACTION_ACCEPT,
					SourceNodes:      []string{"*"},
					DestinationNodes: []string{"*"},
					SourceCidrs:      []string{"*"},
					DestinationCidrs: []string{"*"},
				},
			},
			{
				NetworkACL: &v1.NetworkACL{
					Name:             "acl2",
					Priority:         1,
					Action:           v1.ACLAction_ACTION_ACCEPT,
					SourceNodes:      []string{"*"},
					DestinationNodes: []string{"*"},
					SourceCidrs:      []string{"*"},
					DestinationCidrs: []string{"*"},
				},
			},
			{
				NetworkACL: &v1.NetworkACL{
					Name:             "acl3",
					Priority:         2,
					Action:           v1.ACLAction_ACTION_ACCEPT,
					SourceNodes:      []string{"*"},
					DestinationNodes: []string{"*"},
					SourceCidrs:      []string{"*"},
					DestinationCidrs: []string{"*"},
				},
			},
		}
		for _, acl := range acls {
			err := nw.PutNetworkACL(context.Background(), acl.NetworkACL)
			if err != nil {
				t.Fatalf("put network acl: %v", err)
			}
		}

		// List the ACLs
		got, err := nw.ListNetworkACLs(context.Background())
		if err != nil {
			t.Fatalf("list network acls: %v", err)
		}
		got.Sort(types.SortAscending)
		if len(got) != len(acls) {
			t.Fatalf("expected %d acls, got %d", len(acls), len(got))
		}
		for i, acl := range acls {
			if !acl.Equals(got[i]) {
				t.Fatalf("expected %v, got %v", acl, got[i])
			}
		}
	})
}

func TestNetworkRoutes(t *testing.T) {
	t.Parallel()

	t.Run("GetPutRoutes", func(t *testing.T) {
		t.Parallel()
		nw := setupTest(t)

		t.Run("ValidRoutes", func(t *testing.T) {
			t.Parallel()
			tc := []struct {
				name  string
				route types.Route
			}{
				{
					name: "full-ipv4-tunnel",
					route: types.Route{
						Route: &v1.Route{
							Name:             "full-ipv4-tunnel",
							Node:             "nodea",
							DestinationCidrs: []string{"0.0.0.0/0"},
						},
					},
				},
				{
					name: "full-ipv6-tunnel",
					route: types.Route{
						Route: &v1.Route{
							Name:             "full-ipv6-tunnel",
							Node:             "nodea",
							DestinationCidrs: []string{"::/0"},
						},
					},
				},
				{
					name: "full-tunnel",
					route: types.Route{
						Route: &v1.Route{
							Name:             "full-tunnel",
							Node:             "nodea",
							DestinationCidrs: []string{"::/0", "0.0.0.0/0"},
						},
					},
				},
				{
					name: "internal-ipv4-route",
					route: types.Route{
						Route: &v1.Route{
							Name:             "internal-ipv4-route",
							Node:             "nodea",
							DestinationCidrs: []string{"10.0.0.0/8"},
						},
					},
				},
				{
					name: "internal-ipv6-route",
					route: types.Route{
						Route: &v1.Route{
							Name:             "internal-ipv6-route",
							Node:             "nodea",
							DestinationCidrs: []string{"2001:db8::/32"},
						},
					},
				},
			}

			for _, tt := range tc {
				testCase := tt
				t.Run(tt.name, func(t *testing.T) {
					t.Parallel()
					err := nw.PutRoute(context.Background(), testCase.route.Route)
					if err != nil {
						t.Fatalf("put route: %v", err)
					}
					got, err := nw.GetRoute(context.Background(), testCase.route.GetName())
					if err != nil {
						t.Fatalf("get route: %v", err)
					}
					if !testCase.route.Equals(&got) {
						t.Fatalf("expected %v, got %v", testCase.route, got)
					}
				})
			}
		})

		t.Run("InvalidRoutes", func(t *testing.T) {
			t.Parallel()
			nw := setupTest(t)
			tc := []struct {
				name  string
				route types.Route
			}{
				{
					name: "empty-name",
					route: types.Route{
						Route: &v1.Route{
							Name:             "",
							Node:             "nodea",
							DestinationCidrs: []string{"::/0"},
						},
					},
				},
				{
					name: "empty-node",
					route: types.Route{
						Route: &v1.Route{
							Name:             "route",
							Node:             "",
							DestinationCidrs: []string{"::/0"},
						},
					},
				},
				{
					name: "empty-cidrs",
					route: types.Route{
						Route: &v1.Route{
							Name:             "route",
							Node:             "node-a",
							DestinationCidrs: []string{},
						},
					},
				},
				{
					name: "invalid-route-id",
					route: types.Route{
						Route: &v1.Route{
							Name:             "route/invalid",
							Node:             "node-a",
							DestinationCidrs: []string{"::/0"},
						},
					},
				},
				{
					name: "invalid-node-id",
					route: types.Route{
						Route: &v1.Route{
							Name:             "route",
							Node:             "nodea/nodeb",
							DestinationCidrs: []string{"::/0"},
						},
					},
				},
				{
					name: "invalid-next-hop-node-id",
					route: types.Route{
						Route: &v1.Route{
							Name:             "route",
							Node:             "node-1",
							DestinationCidrs: []string{"::/0"},
							NextHopNode:      "nodea/nodeb",
						},
					},
				},
				{
					name: "invalid-network-cidrs",
					route: types.Route{
						Route: &v1.Route{
							Name:             "route",
							Node:             "node-1",
							DestinationCidrs: []string{"invalid/cidr"},
						},
					},
				},
			}

			for _, tt := range tc {
				testCase := tt
				t.Run(tt.name, func(t *testing.T) {
					t.Parallel()
					err := nw.PutRoute(context.Background(), testCase.route.Route)
					if err == nil {
						t.Fatalf("expected error, got nil")
					}
					if !errors.Is(err, storage.ErrInvalidRoute) {
						t.Errorf("expected %v, got %v", storage.ErrInvalidRoute, err)
					}
				})
			}
		})
	})

	t.Run("GetRoutesByNode", func(t *testing.T) {
		t.Parallel()

		routes := []types.Route{
			{
				Route: &v1.Route{
					Name:             "node-a-route",
					Node:             "node-a",
					DestinationCidrs: []string{"::/0"},
				},
			},
			{
				Route: &v1.Route{
					Name:             "node-b-route",
					Node:             "node-b",
					DestinationCidrs: []string{"::/0"},
				},
			},
		}

		nw := setupTest(t)
		for _, route := range routes {
			err := nw.PutRoute(context.Background(), route.Route)
			if err != nil {
				t.Fatalf("put route: %v", err)
			}
		}
		nodeARoutes, err := nw.GetRoutesByNode(context.Background(), "node-a")
		if err != nil {
			t.Fatalf("get routes by node: %v", err)
		}
		if len(nodeARoutes) != 1 {
			t.Fatalf("expected 1 route, got %d", len(nodeARoutes))
		}
		if !routes[0].Equals(&nodeARoutes[0]) {
			t.Fatalf("expected %v, got %v", routes[0], nodeARoutes[0])
		}
		nodeBRoutes, err := nw.GetRoutesByNode(context.Background(), "node-b")
		if err != nil {
			t.Fatalf("get routes by node: %v", err)
		}
		if len(nodeBRoutes) != 1 {
			t.Fatalf("expected 1 route, got %d", len(nodeBRoutes))
		}
		if !routes[1].Equals(&nodeBRoutes[0]) {
			t.Fatalf("expected %v, got %v", routes[1], nodeBRoutes[0])
		}
	})

	t.Run("GetRoutesByCIDR", func(t *testing.T) {
		t.Parallel()

		routes := []types.Route{
			{
				Route: &v1.Route{
					Name:             "node-a-route",
					Node:             "node-a",
					DestinationCidrs: []string{"10.0.0.0/8"},
				},
			},
			{
				Route: &v1.Route{
					Name:             "node-b-route",
					Node:             "node-b",
					DestinationCidrs: []string{"192.168.0.0/16"},
				},
			},
		}

		nw := setupTest(t)
		for _, route := range routes {
			err := nw.PutRoute(context.Background(), route.Route)
			if err != nil {
				t.Fatalf("put route: %v", err)
			}
		}

		nodeARoutes, err := nw.GetRoutesByCIDR(context.Background(), netip.MustParsePrefix("10.0.0.0/8"))
		if err != nil {
			t.Fatalf("get routes by cidr: %v", err)
		}
		if len(nodeARoutes) != 1 {
			t.Fatalf("expected 1 route, got %d", len(nodeARoutes))
		}
		if !routes[0].Equals(&nodeARoutes[0]) {
			t.Fatalf("expected %v, got %v", routes[0], nodeARoutes[0])
		}

		nodeBRoutes, err := nw.GetRoutesByCIDR(context.Background(), netip.MustParsePrefix("192.168.0.0/16"))
		if err != nil {
			t.Fatalf("get routes by cidr: %v", err)
		}
		if len(nodeBRoutes) != 1 {
			t.Fatalf("expected 1 route, got %d", len(nodeBRoutes))
		}
		if !routes[1].Equals(&nodeBRoutes[0]) {
			t.Fatalf("expected %v, got %v", routes[1], nodeBRoutes[0])
		}
	})

	t.Run("DeleteRoutes", func(t *testing.T) {
		t.Parallel()
		// Put a route, make sure we can delete it, make sure further delete calls don't fail
		nw := setupTest(t)
		route := &types.Route{
			Route: &v1.Route{
				Name:             "route",
				Node:             "node-a",
				DestinationCidrs: []string{"::/0"},
			},
		}
		err := nw.PutRoute(context.Background(), route.Route)
		if err != nil {
			t.Fatalf("put route: %v", err)
		}
		// Make sure its there
		_, err = nw.GetRoute(context.Background(), route.GetName())
		if err != nil {
			t.Fatalf("get route: %v", err)
		}
		// Delete it
		err = nw.DeleteRoute(context.Background(), route.GetName())
		if err != nil {
			t.Fatalf("delete route: %v", err)
		}
		// Make sure its gone
		_, err = nw.GetRoute(context.Background(), route.GetName())
		if err == nil {
			t.Fatalf("expected error, got nil")
		} else if !errors.Is(err, storage.ErrRouteNotFound) {
			t.Fatalf("expected %v, got %v", storage.ErrRouteNotFound, err)
		}
		// Further delete calls should not error
		err = nw.DeleteRoute(context.Background(), route.GetName())
		if err != nil {
			t.Fatalf("delete route: %v", err)
		}
	})

	t.Run("ListRoutes", func(t *testing.T) {
		t.Parallel()
		routes := []types.Route{
			{
				Route: &v1.Route{
					Name:             "node-a-route",
					Node:             "node-a",
					DestinationCidrs: []string{"10.0.0.0/8"},
				},
			},
			{
				Route: &v1.Route{
					Name:             "node-b-route",
					Node:             "node-b",
					DestinationCidrs: []string{"192.168.0.0/16"},
				},
			},
		}
		nw := setupTest(t)
		for _, route := range routes {
			err := nw.PutRoute(context.Background(), route.Route)
			if err != nil {
				t.Fatalf("put route: %v", err)
			}
		}
		got, err := nw.ListRoutes(context.Background())
		if err != nil {
			t.Fatalf("list routes: %v", err)
		}
		got.Sort()
		if len(got) != len(routes) {
			t.Fatalf("expected %d routes, got %d", len(routes), len(got))
		}
		for i, route := range routes {
			if !route.Equals(&got[i]) {
				t.Fatalf("expected %v, got %v", route, got[i])
			}
		}
	})
}

func setupTest(t *testing.T) Networking {
	t.Helper()
	db, err := badgerdb.NewInMemory(badgerdb.Options{})
	if err != nil {
		t.Fatalf("create test db: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
	})
	return New(db)
}
