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
	"context"
	"net/netip"
	"testing"
	"time"

	v1 "github.com/webmeshproj/api/go/v1"

	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// NewNetworkingFunc is a function that creates a new Networking implementation.
type NewNetworkingFunc func(t *testing.T) storage.Networking

// TestNetworkingStorageConformance tests that a Networking implementation conforms to the interface.
func TestNetworkingStorageConformance(t *testing.T, builder NewNetworkingFunc) {
	t.Run("NetworkingConformance", func(t *testing.T) {
		t.Run("Routes", func(t *testing.T) {
			t.Run("GetPutRoutes", func(t *testing.T) {
				nw := builder(t)

				t.Run("ValidRoutes", func(t *testing.T) {
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
									DestinationCIDRs: []string{"0.0.0.0/0"},
								},
							},
						},
						{
							name: "full-ipv6-tunnel",
							route: types.Route{
								Route: &v1.Route{
									Name:             "full-ipv6-tunnel",
									Node:             "nodea",
									DestinationCIDRs: []string{"::/0"},
								},
							},
						},
						{
							name: "full-tunnel",
							route: types.Route{
								Route: &v1.Route{
									Name:             "full-tunnel",
									Node:             "nodea",
									DestinationCIDRs: []string{"::/0", "0.0.0.0/0"},
								},
							},
						},
						{
							name: "internal-ipv4-route",
							route: types.Route{
								Route: &v1.Route{
									Name:             "internal-ipv4-route",
									Node:             "nodea",
									DestinationCIDRs: []string{"10.0.0.0/8"},
								},
							},
						},
						{
							name: "internal-ipv6-route",
							route: types.Route{
								Route: &v1.Route{
									Name:             "internal-ipv6-route",
									Node:             "nodea",
									DestinationCIDRs: []string{"2001:db8::/32"},
								},
							},
						},
					}

					for _, tt := range tc {
						testCase := tt
						t.Run(tt.name, func(t *testing.T) {
							err := nw.PutRoute(context.Background(), types.Route{Route: testCase.route.Route})
							if err != nil {
								t.Fatalf("put route: %v", err)
							}
							var got types.Route
							ok := Eventually[error](func() error {
								got, err = nw.GetRoute(context.Background(), testCase.route.GetName())
								return err
							}).ShouldNotError(time.Second*10, time.Second)
							if !ok {
								t.Fatalf("get route: %v", err)
							}
							if !testCase.route.Equals(&got) {
								t.Fatalf("expected %v, got %v", testCase.route, got)
							}
						})
					}
				})

				t.Run("InvalidRoutes", func(t *testing.T) {
					nw := builder(t)
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
									DestinationCIDRs: []string{"::/0"},
								},
							},
						},
						{
							name: "empty-node",
							route: types.Route{
								Route: &v1.Route{
									Name:             "route",
									Node:             "",
									DestinationCIDRs: []string{"::/0"},
								},
							},
						},
						{
							name: "empty-cidrs",
							route: types.Route{
								Route: &v1.Route{
									Name:             "route",
									Node:             "node-a",
									DestinationCIDRs: []string{},
								},
							},
						},
						{
							name: "invalid-route-id",
							route: types.Route{
								Route: &v1.Route{
									Name:             "route/invalid",
									Node:             "node-a",
									DestinationCIDRs: []string{"::/0"},
								},
							},
						},
						{
							name: "invalid-node-id",
							route: types.Route{
								Route: &v1.Route{
									Name:             "route",
									Node:             "nodea/nodeb",
									DestinationCIDRs: []string{"::/0"},
								},
							},
						},
						{
							name: "invalid-next-hop-node-id",
							route: types.Route{
								Route: &v1.Route{
									Name:             "route",
									Node:             "node-1",
									DestinationCIDRs: []string{"::/0"},
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
									DestinationCIDRs: []string{"invalid/cidr"},
								},
							},
						},
					}

					for _, tt := range tc {
						testCase := tt
						t.Run(tt.name, func(t *testing.T) {
							err := nw.PutRoute(context.Background(), types.Route{Route: testCase.route.Route})
							if err == nil {
								t.Fatalf("expected error, got nil")
							}
							if !errors.IsInvalidRoute(err) {
								t.Errorf("expected %v, got %v", errors.ErrInvalidRoute, err)
							}
						})
					}
				})
			})

			t.Run("GetRoutesByNode", func(t *testing.T) {
				routes := []types.Route{
					{
						Route: &v1.Route{
							Name:             "node-a-route",
							Node:             "node-a",
							DestinationCIDRs: []string{"::/0"},
						},
					},
					{
						Route: &v1.Route{
							Name:             "node-b-route",
							Node:             "node-b",
							DestinationCIDRs: []string{"::/0"},
						},
					},
				}
				nw := builder(t)
				for _, route := range routes {
					err := nw.PutRoute(context.Background(), types.Route{Route: route.Route})
					if err != nil {
						t.Fatalf("put route: %v", err)
					}
				}
				var nodeARoutes []types.Route
				var err error
				ok := Eventually[int](func() int {
					nodeARoutes, err = nw.GetRoutesByNode(context.Background(), "node-a")
					if err != nil {
						t.Log("Error fetching routes:", err)
						return 0
					}
					return len(nodeARoutes)
				}).ShouldEqual(time.Second*10, time.Second, 1)
				if !ok {
					t.Fatalf("Did not get expected number of routes")
				}
				if !routes[0].Equals(&nodeARoutes[0]) {
					t.Fatalf("expected %v, got %v", routes[0], nodeARoutes[0])
				}
				var nodeBRoutes []types.Route
				ok = Eventually[int](func() int {
					nodeBRoutes, err = nw.GetRoutesByNode(context.Background(), "node-b")
					if err != nil {
						t.Log("Error fetching routes:", err)
						return 0
					}
					return len(nodeBRoutes)
				}).ShouldEqual(time.Second*10, time.Second, 1)
				if !ok {
					t.Fatalf("Did not get expected number of routes")
				}
				if !routes[1].Equals(&nodeBRoutes[0]) {
					t.Fatalf("expected %v, got %v", routes[0], nodeBRoutes[0])
				}
			})

			t.Run("GetRoutesByCIDR", func(t *testing.T) {
				routes := []types.Route{
					{
						Route: &v1.Route{
							Name:             "node-a-route",
							Node:             "node-a",
							DestinationCIDRs: []string{"10.0.0.0/8"},
						},
					},
					{
						Route: &v1.Route{
							Name:             "node-b-route",
							Node:             "node-b",
							DestinationCIDRs: []string{"192.168.0.0/16"},
						},
					},
				}

				nw := builder(t)
				for _, route := range routes {
					err := nw.PutRoute(context.Background(), types.Route{Route: route.Route})
					if err != nil {
						t.Fatalf("put route: %v", err)
					}
				}

				// We should eventually see node A's routes
				var nodeARoutes types.Routes
				var err error
				ok := Eventually[int](func() int {
					nodeARoutes, err = nw.GetRoutesByCIDR(context.Background(), netip.MustParsePrefix("10.0.0.0/8"))
					if err != nil {
						t.Log("Error fetching routes:", err)
						return 0
					}
					return len(nodeARoutes)
				}).ShouldEqual(time.Second*10, time.Second, 1)
				if !ok {
					t.Fatalf("Did not get expected number of routes")
				}
				if !routes[0].Equals(&nodeARoutes[0]) {
					t.Fatalf("expected %v, got %v", routes[0], nodeARoutes[0])
				}
				// Same for node B
				var nodeBRoutes types.Routes
				ok = Eventually[int](func() int {
					nodeBRoutes, err = nw.GetRoutesByCIDR(context.Background(), netip.MustParsePrefix("192.168.0.0/16"))
					if err != nil {
						t.Log("Error fetching routes:", err)
						return 0
					}
					return len(nodeBRoutes)
				}).ShouldEqual(time.Second*10, time.Second, 1)
				if !ok {
					t.Fatalf("expected 1 route, got %d", len(nodeBRoutes))
				}
				if !routes[1].Equals(&nodeBRoutes[0]) {
					t.Fatalf("expected %v, got %v", routes[1], nodeBRoutes[0])
				}
			})

			t.Run("DeleteRoutes", func(t *testing.T) {
				// Put a route, make sure we can delete it, make sure further delete calls don't fail
				nw := builder(t)
				route := &types.Route{
					Route: &v1.Route{
						Name:             "route",
						Node:             "node-a",
						DestinationCIDRs: []string{"::/0"},
					},
				}
				err := nw.PutRoute(context.Background(), types.Route{Route: route.Route})
				if err != nil {
					t.Fatalf("put route: %v", err)
				}
				// Make sure its eventually there
				ok := Eventually[error](func() error {
					_, err = nw.GetRoute(context.Background(), route.GetName())
					return err
				}).ShouldNotError(time.Second*10, time.Second)
				if !ok {
					t.Fatalf("get route: %v", err)
				}
				// Delete it
				err = nw.DeleteRoute(context.Background(), route.GetName())
				if err != nil {
					t.Fatalf("delete route: %v", err)
				}
				// Make sure its eventually gone
				ok = Eventually[error](func() error {
					_, err = nw.GetRoute(context.Background(), route.GetName())
					return err
				}).ShouldErrorWith(time.Second*10, time.Second, errors.ErrRouteNotFound)
				if !ok {
					t.Fatalf("get deleted route did not error")
				}
				// Further delete calls should not error
				err = nw.DeleteRoute(context.Background(), route.GetName())
				if err != nil {
					t.Fatalf("delete route: %v", err)
				}
			})

			t.Run("ListRoutes", func(t *testing.T) {
				routes := []types.Route{
					{
						Route: &v1.Route{
							Name:             "node-a-route",
							Node:             "node-a",
							DestinationCIDRs: []string{"10.0.0.0/8"},
						},
					},
					{
						Route: &v1.Route{
							Name:             "node-b-route",
							Node:             "node-b",
							DestinationCIDRs: []string{"192.168.0.0/16"},
						},
					},
				}
				nw := builder(t)
				for _, route := range routes {
					err := nw.PutRoute(context.Background(), types.Route{Route: route.Route})
					if err != nil {
						t.Fatalf("put route: %v", err)
					}
				}
				// We should eventually see both routes
				var got types.Routes
				var err error
				ok := Eventually[int](func() int {
					got, err = nw.ListRoutes(context.Background())
					if err != nil {
						t.Log("Error fetching routes:", err)
						return 0
					}
					return len(got)
				}).ShouldEqual(time.Second*10, time.Second, 2)
				if !ok {
					t.Fatalf("Did not get expected number of routes")
				}
				if len(got) != len(routes) {
					t.Fatalf("expected %d routes, got %d", len(routes), len(got))
				}
				got.Sort()
				for i, route := range routes {
					if !route.Equals(&got[i]) {
						t.Fatalf("expected %v, got %v", route, got[i])
					}
				}
			})
		})

		t.Run("NetworkACLs", func(t *testing.T) {

			t.Run("GetPutACL", func(t *testing.T) {
				nw := builder(t)
				t.Run("ValidACLs", func(t *testing.T) {
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
									SourceCIDRs:      []string{"*"},
									DestinationCIDRs: []string{"*"},
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
									SourceCIDRs:      []string{"*"},
									DestinationCIDRs: []string{"*"},
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
									SourceCIDRs:      []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
									DestinationCIDRs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
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
									SourceCIDRs:      []string{"2001:db8::/32", "2001:db8:ffff::/48"},
									DestinationCIDRs: []string{"2001:db8::/32", "2001:db8:ffff::/48"},
								},
							},
						},
					}
					for _, tt := range tc {
						testCase := tt
						t.Run(tt.name, func(t *testing.T) {
							err := nw.PutNetworkACL(context.Background(), *testCase.acl)
							if err != nil {
								t.Fatalf("put network acl: %v", err)
							}
							// It should eventually get stored
							var got types.NetworkACL
							ok := Eventually[error](func() error {
								got, err = nw.GetNetworkACL(context.Background(), testCase.acl.GetName())
								return err
							}).ShouldNotError(time.Second*10, time.Second)
							if !ok {
								t.Fatalf("get network acl: %v", err)
							}
							if !testCase.acl.Equals(got) {
								t.Fatalf("expected %v, got %v", testCase.acl, got)
							}
						})
					}
				})

				t.Run("InvalidACLs", func(t *testing.T) {
					nw := builder(t)
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
									SourceCIDRs:      []string{"*"},
									DestinationCIDRs: []string{"*"},
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
									SourceCIDRs:      []string{"*"},
									DestinationCIDRs: []string{"*"},
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
									SourceCIDRs:      []string{"*"},
									DestinationCIDRs: []string{"*"},
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
									SourceCIDRs:      []string{"*"},
									DestinationCIDRs: []string{"*"},
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
									SourceCIDRs:      []string{"*"},
									DestinationCIDRs: []string{"*"},
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
									SourceCIDRs:      []string{"invalid/cidr1", "invalid/cidr2"},
									DestinationCIDRs: []string{"*"},
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
									SourceCIDRs:      []string{"*"},
									DestinationCIDRs: []string{"invalid/cidr1", "invalid/cidr2"},
								},
							},
						},
					}
					for _, tt := range tc {
						testCase := tt
						t.Run(tt.name, func(t *testing.T) {
							err := nw.PutNetworkACL(context.Background(), *testCase.acl)
							if err == nil {
								t.Fatalf("expected error, got nil")
							}
							if !errors.IsInvalidACL(err) {
								t.Errorf("expected %v, got %v", errors.ErrInvalidACL, err)
							}
						})
					}
				})
			})

			t.Run("DeleteACLs", func(t *testing.T) {
				nw := builder(t)
				// Put a valid ACL, we should be able to delete it
				// and further calls to delete should not error.
				acl := types.NetworkACL{
					NetworkACL: &v1.NetworkACL{
						Name:             "wildcard-acl",
						Priority:         0,
						Action:           v1.ACLAction_ACTION_ACCEPT,
						SourceNodes:      []string{"*"},
						DestinationNodes: []string{"*"},
						SourceCIDRs:      []string{"*"},
						DestinationCIDRs: []string{"*"},
					},
				}
				err := nw.PutNetworkACL(context.Background(), acl)
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
				} else if !errors.IsACLNotFound(err) {
					t.Fatalf("expected %v, got %v", errors.ErrACLNotFound, err)
				}
				// Further calls to delete should not error
				err = nw.DeleteNetworkACL(context.Background(), acl.GetName())
				if err != nil {
					t.Fatalf("delete network acl: %v", err)
				}
			})

			t.Run("ListACLs", func(t *testing.T) {
				// Put a few ACLs
				nw := builder(t)
				acls := []types.NetworkACL{
					{
						NetworkACL: &v1.NetworkACL{
							Name:             "acl1",
							Priority:         0,
							Action:           v1.ACLAction_ACTION_ACCEPT,
							SourceNodes:      []string{"*"},
							DestinationNodes: []string{"*"},
							SourceCIDRs:      []string{"*"},
							DestinationCIDRs: []string{"*"},
						},
					},
					{
						NetworkACL: &v1.NetworkACL{
							Name:             "acl2",
							Priority:         1,
							Action:           v1.ACLAction_ACTION_ACCEPT,
							SourceNodes:      []string{"*"},
							DestinationNodes: []string{"*"},
							SourceCIDRs:      []string{"*"},
							DestinationCIDRs: []string{"*"},
						},
					},
					{
						NetworkACL: &v1.NetworkACL{
							Name:             "acl3",
							Priority:         2,
							Action:           v1.ACLAction_ACTION_ACCEPT,
							SourceNodes:      []string{"*"},
							DestinationNodes: []string{"*"},
							SourceCIDRs:      []string{"*"},
							DestinationCIDRs: []string{"*"},
						},
					},
				}
				for _, acl := range acls {
					err := nw.PutNetworkACL(context.Background(), acl)
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
		})
	})
}
