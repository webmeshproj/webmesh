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
	"net/netip"
	"testing"

	v1 "github.com/webmeshproj/api/v1"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/meshdb/peers"
)

func TestGetEdge(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server, close := newTestServer(ctx, t)
	defer close()

	// Place a dummy peer
	key, err := wgtypes.GenerateKey()
	if err != nil {
		t.Errorf("GenerateKey() error = %v", err)
		return
	}
	_, err = peers.New(server.store.DB()).Put(ctx, &peers.PutOptions{
		ID:          "foo",
		PublicKey:   key.PublicKey(),
		NetworkIPv6: netip.MustParsePrefix("2001:db8::/64"),
	})
	if err != nil {
		t.Errorf("Put() error = %v", err)
		return
	}
	// Place an edge from us to the dummy peer
	_, err = server.PutEdge(ctx, &v1.MeshEdge{
		Source: server.store.ID(),
		Target: "foo",
	})
	if err != nil {
		t.Errorf("PutEdge() error = %v", err)
		return
	}

	tc := []testCase[v1.MeshEdge]{
		{
			name: "no source node",
			code: codes.InvalidArgument,
			req:  &v1.MeshEdge{Source: "", Target: "bar"},
		},
		{
			name: "no target node",
			code: codes.InvalidArgument,
			req:  &v1.MeshEdge{Source: "foo", Target: ""},
		},
		{
			name: "non-existent edge",
			req:  &v1.MeshEdge{Source: "foo", Target: "bar"},
			code: codes.NotFound,
		},
		{
			name: "existing edge",
			req:  &v1.MeshEdge{Source: server.store.ID(), Target: "foo"},
			code: codes.OK,
		},
	}

	runTestCases(t, tc, server.GetEdge)
}
