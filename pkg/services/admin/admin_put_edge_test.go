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
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"

	"github.com/webmeshproj/node/pkg/meshdb/peers"
)

func TestPutEdge(t *testing.T) {
	t.Parallel()

	server, closer := newTestServer(context.Background(), t)
	defer closer()

	// Pre register the nodes
	p := peers.New(server.store.Storage())
	for _, peer := range []string{"foo", "baz"} {
		key, err := wgtypes.GenerateKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		_, err = p.Put(context.Background(), &peers.PutOptions{
			ID:        peer,
			PublicKey: key.PublicKey(),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	tt := []testCase[v1.MeshEdge]{
		{
			name: "no target",
			code: codes.InvalidArgument,
			req: &v1.MeshEdge{
				Source: "foo",
			},
		},
		{
			name: "no source",
			code: codes.InvalidArgument,
			req: &v1.MeshEdge{
				Target: "baz",
			},
		},
		{
			name: "invalid target",
			code: codes.InvalidArgument,
			req: &v1.MeshEdge{
				Source: "foo",
				Target: "baz,",
			},
		},
		{
			name: "invalid source",
			code: codes.InvalidArgument,
			req: &v1.MeshEdge{
				Source: "foo,",
				Target: "baz",
			},
		},
		{
			name: "valid edge",
			code: codes.OK,
			req: &v1.MeshEdge{
				Source: "foo",
				Target: "baz",
				Weight: 0,
			},
			tval: func(t *testing.T) {
				edge, err := server.GetEdge(context.Background(), &v1.MeshEdge{
					Source: "foo",
					Target: "baz",
				})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if edge == nil {
					t.Fatal("expected edge, got nil")
				}
				if edge.Source != "foo" {
					t.Fatalf("expected source foo, got %s", edge.Source)
				}
				if edge.Target != "baz" {
					t.Fatalf("expected target baz, got %s", edge.Target)
				}
				if edge.Weight != 0 {
					t.Fatalf("expected weight 0, got %d", edge.Weight)
				}
			},
		},
	}

	runTestCases(t, tt, server.PutEdge)
}
