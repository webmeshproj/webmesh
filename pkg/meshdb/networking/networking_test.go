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
	"testing"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/storage/badgerdb"
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
				acl  *ACL
			}{
				{
					name: "wildcard-acl",
					acl: &ACL{
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
					acl: &ACL{
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
					acl: &ACL{
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
					acl: &ACL{
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
					if !testCase.acl.Equals(&got) {
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
				acl  *ACL
			}{
				{
					name: "empty-name",
					acl: &ACL{
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
					acl: &ACL{
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
					acl: &ACL{
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
					acl: &ACL{
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
					acl: &ACL{
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
					acl: &ACL{
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
					acl: &ACL{
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
					if !errors.Is(err, ErrInvalidACL) {
						t.Errorf("expected %v, got %v", ErrInvalidACL, err)
					}
				})
			}
		})
	})

	t.Run("DeleteACLs", func(t *testing.T) {
		t.Parallel()
	})

	t.Run("ListACLs", func(t *testing.T) {
		t.Parallel()
	})
}

func TestNetworkRoutes(t *testing.T) {
	t.Parallel()

	t.Run("GetPutRoutes", func(t *testing.T) {
		t.Parallel()
	})

	t.Run("GetRoutesByNode", func(t *testing.T) {
		t.Parallel()
	})

	t.Run("GetRoutesByCIDR", func(t *testing.T) {
		t.Parallel()
	})

	t.Run("DeleteRoutes", func(t *testing.T) {
		t.Parallel()
	})

	t.Run("ListRoutes", func(t *testing.T) {
		t.Parallel()
	})
}

func setupTest(t *testing.T) Networking {
	t.Helper()
	db, err := badgerdb.New(badgerdb.Options{InMemory: true})
	if err != nil {
		t.Fatalf("create test db: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
	})
	return New(db)
}
