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
	"sort"
	"testing"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slices"

	"github.com/webmeshproj/webmesh/pkg/storage/backends/badgerdb"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb/networking"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb/rbac"
)

func TestWireGuardPeersWithACLs(t *testing.T) {
	t.Parallel()

	tt := []struct {
		name      string
		peers     []*v1.MeshNode
		groups    map[string][]string
		acls      []*v1.NetworkACL
		edges     map[string][]string // peerID -> []peerID
		wantPeers map[string][]string // peerID -> []peerID
	}{
		{
			name: "no ACLs",
			peers: []*v1.MeshNode{
				{Id: "a", PrivateIpv4: "172.16.0.1/32", PrivateIpv6: "2001:db8::1/128"},
				{Id: "b", PrivateIpv4: "172.16.0.1/32", PrivateIpv6: "2001:db8::1/128"},
				{Id: "c", PrivateIpv4: "172.16.0.1/32", PrivateIpv6: "2001:db8::1/128"},
			},
			edges: map[string][]string{
				"a": {"b", "c"},
				"b": {"a", "c"},
				"c": {"a", "b"},
			},
			acls: []*v1.NetworkACL{},
			wantPeers: map[string][]string{
				"a": {},
				"b": {},
				"c": {},
			},
		},
		{
			name: "deny-all ACL",
			peers: []*v1.MeshNode{
				{Id: "a", PrivateIpv4: "172.16.0.1/32", PrivateIpv6: "2001:db8::1/128"},
				{Id: "b", PrivateIpv4: "172.16.0.1/32", PrivateIpv6: "2001:db8::1/128"},
				{Id: "c", PrivateIpv4: "172.16.0.1/32", PrivateIpv6: "2001:db8::1/128"},
			},
			edges: map[string][]string{
				"a": {"b", "c"},
				"b": {"a", "c"},
				"c": {"a", "b"},
			},
			acls: []*v1.NetworkACL{
				{
					Name:             "deny-all",
					Priority:         0,
					Action:           v1.ACLAction_ACTION_DENY,
					SourceNodes:      []string{"*"},
					DestinationNodes: []string{"*"},
					SourceCidrs:      []string{"*"},
					DestinationCidrs: []string{"*"},
				},
			},
			wantPeers: map[string][]string{
				"a": {},
				"b": {},
				"c": {},
			},
		},
		{
			name: "accept-all ACL",
			peers: []*v1.MeshNode{
				{Id: "a", PrivateIpv4: "172.16.0.1/32", PrivateIpv6: "2001:db8::1/128"},
				{Id: "b", PrivateIpv4: "172.16.0.1/32", PrivateIpv6: "2001:db8::1/128"},
				{Id: "c", PrivateIpv4: "172.16.0.1/32", PrivateIpv6: "2001:db8::1/128"},
			},
			edges: map[string][]string{
				"a": {"b", "c"},
				"b": {"a", "c"},
				"c": {"a", "b"},
			},
			acls: []*v1.NetworkACL{
				{
					Name:             "allow-all",
					Priority:         0,
					Action:           v1.ACLAction_ACTION_ACCEPT,
					SourceNodes:      []string{"*"},
					DestinationNodes: []string{"*"},
					SourceCidrs:      []string{"*"},
					DestinationCidrs: []string{"*"},
				},
			},
			wantPeers: map[string][]string{
				"a": {"b", "c"},
				"b": {"a", "c"},
				"c": {"a", "b"},
			},
		},
		{
			name: "allow-a-b ACL",
			peers: []*v1.MeshNode{
				{Id: "a", PrivateIpv4: "172.16.0.1/32", PrivateIpv6: "2001:db8::1/128"},
				{Id: "b", PrivateIpv4: "172.16.0.1/32", PrivateIpv6: "2001:db8::1/128"},
				{Id: "c", PrivateIpv4: "172.16.0.1/32", PrivateIpv6: "2001:db8::1/128"},
			},
			edges: map[string][]string{
				"a": {"b", "c"},
				"b": {"a", "c"},
				"c": {"a", "b"},
			},
			acls: []*v1.NetworkACL{
				{
					Name:             "allow-a-b",
					Priority:         0,
					Action:           v1.ACLAction_ACTION_ACCEPT,
					SourceNodes:      []string{"a", "b"},
					DestinationNodes: []string{"a", "b"},
				},
			},
			wantPeers: map[string][]string{
				"a": {"b"},
				"b": {"a"},
				"c": {},
			},
		},
		{
			name: "allow-a-b-c ACL",
			peers: []*v1.MeshNode{
				{Id: "a", PrivateIpv4: "172.16.0.1/32", PrivateIpv6: "2001:db8::1/128"},
				{Id: "b", PrivateIpv4: "172.16.0.1/32", PrivateIpv6: "2001:db8::1/128"},
				{Id: "c", PrivateIpv4: "172.16.0.1/32", PrivateIpv6: "2001:db8::1/128"},
			},
			edges: map[string][]string{
				"a": {"b", "c"},
				"b": {"a", "c"},
				"c": {"a", "b"},
			},
			acls: []*v1.NetworkACL{
				{
					Name:             "allow-a-b-c",
					Priority:         0,
					Action:           v1.ACLAction_ACTION_ACCEPT,
					SourceNodes:      []string{"a", "b", "c"},
					DestinationNodes: []string{"a", "b", "c"},
				},
			},
			wantPeers: map[string][]string{
				"a": {"b", "c"},
				"b": {"a", "c"},
				"c": {"a", "b"},
			},
		},
	}

	for _, tc := range tt {
		testCase := tc
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			// Prepare the test database
			ctx := context.Background()
			db, err := badgerdb.NewInMemory(badgerdb.Options{})
			if err != nil {
				t.Fatalf("create test db: %v", err)
			}
			defer db.Close()
			peerdb := New(db)
			rbacdb := rbac.New(db)
			nwdb := networking.New(db)
			for _, peer := range testCase.peers {
				peer.PublicKey = mustGeneratePublicKey(t)
				if err := peerdb.Put(ctx, peer); err != nil {
					t.Fatalf("create peer: %v", err)
				}
			}
			for groupName, peers := range testCase.groups {
				err := rbacdb.PutGroup(ctx, &v1.Group{
					Name: groupName,
					Subjects: func() []*v1.Subject {
						var out []*v1.Subject
						for _, peerID := range peers {
							out = append(out, &v1.Subject{
								Type: v1.SubjectType_SUBJECT_ALL,
								Name: peerID,
							})
						}
						return out
					}(),
				})
				if err != nil {
					t.Fatalf("create group %q: %v", groupName, err)
				}
			}
			for peerID, edges := range testCase.edges {
				for _, edge := range edges {
					err = peerdb.PutEdge(ctx, &v1.MeshEdge{
						Source: peerID,
						Target: edge,
					})
					if err != nil {
						t.Fatalf("put edge from %q to %q: %v", peerID, edge, err)
					}
				}
			}
			for _, acl := range testCase.acls {
				if err := nwdb.PutNetworkACL(ctx, acl); err != nil {
					t.Fatalf("create network ACL: %v", err)
				}
			}
			// Run the test cases
			for peerID := range testCase.wantPeers {
				peers, err := WireGuardPeersFor(ctx, db, peerID)
				if err != nil {
					t.Fatalf("get WireGuard peers for %q: %v", peerID, err)
				}
				gotPeers := make([]string, 0, len(peers))
				for _, peer := range peers {
					gotPeers = append(gotPeers, peer.Node.Id)
				}
				sort.Strings(gotPeers)
				sort.Strings(testCase.wantPeers[peerID])
				if !slices.Equal(gotPeers, testCase.wantPeers[peerID]) {
					t.Errorf("WireGuardPeersFor(%q) = %v, want %v", peerID, gotPeers, testCase.wantPeers[peerID])
				}
			}
		})
	}
}
