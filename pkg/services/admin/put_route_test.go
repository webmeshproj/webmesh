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

	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc/codes"
)

func TestPutRoute(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server := newTestServer(t)

	tt := []testCase[v1.Route]{
		{
			name: "no route name",
			code: codes.InvalidArgument,
			req:  &v1.Route{},
		},
		{
			name: "no node id",
			code: codes.InvalidArgument,
			req: &v1.Route{
				Name:             "test",
				DestinationCIDRs: []string{"0.0.0.0/0"},
			},
		},
		{
			name: "no destination cidrs",
			code: codes.InvalidArgument,
			req: &v1.Route{
				Name: "test",
				Node: "test",
			},
		},
		{
			name: "invalid destination cidr",
			code: codes.InvalidArgument,
			req: &v1.Route{
				Name:             "test",
				Node:             "test",
				DestinationCIDRs: []string{""},
			},
		},
		{
			name: "invalid node",
			code: codes.InvalidArgument,
			req: &v1.Route{
				Name:             "test",
				Node:             ",test",
				DestinationCIDRs: []string{"0.0.0.0/0"},
			},
		},
		{
			name: "single invalid destination cidr",
			code: codes.InvalidArgument,
			req: &v1.Route{
				Name:             "test",
				Node:             "test",
				DestinationCIDRs: []string{"0.0.0.0/0", ""},
			},
		},
		{
			name: "valid ipv4 route",
			code: codes.OK,
			req: &v1.Route{
				Name:             "test-v4",
				Node:             "test",
				DestinationCIDRs: []string{"0.0.0.0/0"},
			},
			tval: func(t *testing.T) {
				route, err := server.GetRoute(ctx, &v1.Route{Name: "test-v4"})
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				} else if route == nil {
					t.Errorf("expected route to be returned")
				} else if route.Name != "test-v4" {
					t.Errorf("expected route name to be 'test', got: %s", route.Name)
				} else if route.Node != "test" {
					t.Errorf("expected route node to be 'test', got: %s", route.Node)
				} else if len(route.DestinationCIDRs) != 1 {
					t.Errorf("expected route to have 1 destination cidr, got: %d", len(route.DestinationCIDRs))
				} else if route.DestinationCIDRs[0] != "0.0.0.0/0" {
					t.Errorf("expected route destination cidr to be '0.0.0.0/0', got %s", route.DestinationCIDRs[0])
				}
			},
		},
		{
			name: "valid ipv6 route",
			code: codes.OK,
			req: &v1.Route{
				Name:             "test-v6",
				Node:             "test",
				DestinationCIDRs: []string{"::/0"},
			},
			tval: func(t *testing.T) {
				route, err := server.GetRoute(ctx, &v1.Route{Name: "test-v6"})
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				} else if route == nil {
					t.Errorf("expected route to be returned")
				} else if route.Name != "test-v6" {
					t.Errorf("expected route name to be 'test', got: %s", route.Name)
				} else if route.Node != "test" {
					t.Errorf("expected route node to be 'test', got: %s", route.Node)
				} else if len(route.DestinationCIDRs) != 1 {
					t.Errorf("expected route to have 1 destination cidr, got: %d", len(route.DestinationCIDRs))
				} else if route.DestinationCIDRs[0] != "::/0" {
					t.Errorf("expected route destination cidr to be '::/0', got %s", route.DestinationCIDRs[0])
				}
			},
		},
	}

	runTestCases(t, tt, server.PutRoute)
}
