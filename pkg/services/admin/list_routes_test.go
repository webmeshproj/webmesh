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
)

func TestListRoutes(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server := newTestServer(t)

	// Empty condition
	routes, err := server.ListRoutes(ctx, nil)
	if err != nil {
		t.Errorf("ListRoutes() error = %v", err)
		return
	}
	if len(routes.GetItems()) != 0 {
		t.Errorf("ListRoutes() expected empty list, got %v", routes.GetItems())
	}

	// Place a route
	_, err = server.PutRoute(ctx, &v1.Route{
		Name:             "test-route",
		Node:             "foo",
		DestinationCIDRs: []string{"0.0.0.0/0"},
	})
	if err != nil {
		t.Errorf("PutRoute() error = %v", err)
		return
	}

	// Verify route is present
	routes, err = server.ListRoutes(ctx, nil)
	if err != nil {
		t.Errorf("ListRoutes() error = %v", err)
		return
	}

	if len(routes.GetItems()) != 1 {
		t.Errorf("ListRoutes() expected 1 route, got %v", routes.GetItems())
		return
	}
	if routes.GetItems()[0].Name != "test-route" {
		t.Errorf("ListRoutes() expected route name 'test-route', got %v", routes.GetItems()[0].Name)
	}
	if routes.GetItems()[0].Node != "foo" {
		t.Errorf("ListRoutes() expected route node 'foo', got %v", routes.GetItems()[0].Node)
	}
	if len(routes.GetItems()[0].DestinationCIDRs) != 1 {
		t.Errorf("ListRoutes() expected route destination cidrs length 1, got %v", len(routes.GetItems()[0].DestinationCIDRs))
	} else {
		{
			if routes.GetItems()[0].DestinationCIDRs[0] != "0.0.0.0/0" {
				t.Errorf("ListRoutes() expected route destination cidrs '0.0.0.0/0', got %v", routes.GetItems()[0].DestinationCIDRs[0])
			}
		}
	}
}
