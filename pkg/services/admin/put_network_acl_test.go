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

package admin

import (
	"context"
	"testing"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/codes"
)

func TestPutNetworkACL(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)

	tt := []testCase[v1.NetworkACL]{
		{
			name: "no acl name",
			code: codes.InvalidArgument,
			req: &v1.NetworkACL{
				Name:        "",
				Action:      v1.ACLAction_ACTION_ACCEPT,
				SourceNodes: []string{"foo"},
			},
		},
		{
			name: "invalid action",
			code: codes.InvalidArgument,
			req: &v1.NetworkACL{
				Name:        "foo",
				Action:      -1,
				SourceNodes: []string{"foo"},
			},
		},
		{
			name: "empty acl",
			code: codes.InvalidArgument,
			req: &v1.NetworkACL{
				Name:   "foo",
				Action: v1.ACLAction_ACTION_ACCEPT,
			},
		},
		{
			name: "invalid source network cidr",
			code: codes.InvalidArgument,
			req: &v1.NetworkACL{
				Name:        "foo",
				Action:      v1.ACLAction_ACTION_ACCEPT,
				SourceCIDRs: []string{"0.0.0.0/0", "foo"},
			},
		},
		{
			name: "invalid destination network cidr",
			code: codes.InvalidArgument,
			req: &v1.NetworkACL{
				Name:             "foo",
				Action:           v1.ACLAction_ACTION_ACCEPT,
				DestinationCIDRs: []string{"0.0.0.0/0", "foo"},
			},
		},
		{
			name: "invalid source node",
			code: codes.InvalidArgument,
			req: &v1.NetworkACL{
				Name:             "foo",
				Action:           v1.ACLAction_ACTION_ACCEPT,
				SourceNodes:      []string{"foo", "bar", "baz,qux"},
				DestinationCIDRs: []string{"0.0.0.0/0"},
			},
		},
		{
			name: "invalid destination node",
			code: codes.InvalidArgument,
			req: &v1.NetworkACL{
				Name:             "foo",
				Action:           v1.ACLAction_ACTION_ACCEPT,
				DestinationNodes: []string{"foo", "bar", "baz,qux"},
				DestinationCIDRs: []string{"0.0.0.0/0"},
			},
		},
		{
			name: "valid acl",
			code: codes.OK,
			req: &v1.NetworkACL{
				Name:             "foo",
				Action:           v1.ACLAction_ACTION_ACCEPT,
				DestinationNodes: []string{"foo"},
				DestinationCIDRs: []string{"0.0.0.0/0"},
			},
			tval: func(t *testing.T) {
				acl, err := server.GetNetworkACL(context.Background(), &v1.NetworkACL{Name: "foo"})
				if err != nil {
					t.Error(err)
					return
				}
				if acl.Name != "foo" {
					t.Errorf("expected acl name to be foo, got %s", acl.Name)
				}
				if acl.Action != v1.ACLAction_ACTION_ACCEPT {
					t.Errorf("expected acl action to be ACTION_ACCEPT, got %s", acl.Action)
				}
				if len(acl.DestinationNodes) != 1 {
					t.Errorf("expected acl to have 1 destination node, got %d", len(acl.DestinationNodes))

				} else if acl.DestinationNodes[0] != "foo" {
					t.Errorf("expected acl destination node to be foo, got %s", acl.DestinationNodes[0])
				}
				if len(acl.DestinationCIDRs) != 1 {
					t.Errorf("expected acl to have 1 destination cidr, got %d", len(acl.DestinationCIDRs))
				} else if acl.DestinationCIDRs[0] != "0.0.0.0/0" {
					t.Errorf("expected acl destination cidr to be %s, got %s", "0.0.0.0/0", acl.DestinationCIDRs[0])
				}
			},
		},
	}

	runTestCases(t, tt, server.PutNetworkACL)
}
