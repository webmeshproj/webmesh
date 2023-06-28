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

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/meshdb/peers"
)

func TestListEdges(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	server, close := newTestServer(ctx, t)
	defer close()

	// No empty condition

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

	// Verify edge is present
	edges, err := server.ListEdges(ctx, nil)
	if err != nil {
		t.Errorf("ListEdges() error = %v", err)
		return
	}
	var edge *v1.MeshEdge
	for _, e := range edges.GetItems() {
		if e.Source == server.store.ID() && e.Target == "foo" {
			edge = e
			break
		}
	}
	if edge == nil {
		t.Errorf("ListEdges() did not return expected edge")
		return
	}
}
