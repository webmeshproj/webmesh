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

package state

import (
	"context"
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	"github.com/webmeshproj/webmesh/pkg/storage/nutsdb"
)

var (
	ipv6Prefix = "fd00:dead::/48"
	ipv4Prefix = "172.16.0.0/12"
	domain     = "webmesh.internal"

	publicNode  = "public"
	privateNode = "private"

	publicNodePublicAddr = "1.1.1.1"

	publicNodePrivateAddr  = "172.16.0.1/32"
	privateNodePrivateAddr = "172.16.0.2/32"

	rpcPort = 1
)

func TestGetIPv6Prefix(t *testing.T) {
	t.Parallel()

	state, teardown := setupTest(t)
	defer teardown()
	prefix, err := state.GetIPv6Prefix(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if prefix.String() != ipv6Prefix {
		t.Fatalf("expected %s, got %s", ipv6Prefix, prefix)
	}
}

func TestGetIPv4Prefix(t *testing.T) {
	t.Parallel()

	state, teardown := setupTest(t)
	defer teardown()
	prefix, err := state.GetIPv4Prefix(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if prefix.String() != ipv4Prefix {
		t.Fatalf("expected %s, got %s", ipv4Prefix, prefix)
	}
}

func TestGetMeshDomain(t *testing.T) {
	t.Parallel()

	state, teardown := setupTest(t)
	defer teardown()
	got, err := state.GetMeshDomain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if domain != got {
		t.Fatalf("expected %q, got %s", domain, got)
	}
}

func TestListPublicRPCAddresses(t *testing.T) {
	t.Parallel()

	state, teardown := setupTest(t)
	defer teardown()

	addrs, err := state.ListPublicRPCAddresses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 {
		t.Errorf("expected 1 address, got %d", len(addrs))
	}
	for _, addr := range addrs {
		if addr.String() != "1.1.1.1:1" {
			t.Errorf("expected '1.1.1.1:1', got %s", addr)
		}
	}
}

func TestListPeerPublicRPCAddresses(t *testing.T) {
	t.Parallel()

	state, teardown := setupTest(t)
	defer teardown()

	// The private node should have the public node as a public peer
	addrs, err := state.ListPeerPublicRPCAddresses(context.Background(), privateNode)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 {
		t.Errorf("expected 1 address, got %d", len(addrs))
	}
	for _, addr := range addrs {
		if addr.String() != "1.1.1.1:1" {
			t.Errorf("expected '1.1.1.1:1', got %s", addr)
		}
	}

	// The public node should have no public peers
	addrs, err = state.ListPeerPublicRPCAddresses(context.Background(), publicNode)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 0 {
		t.Errorf("expected 0 addresses, got %d", len(addrs))
	}
}

func TestListPeerPrivateRPCAddresses(t *testing.T) {
	t.Parallel()

	state, teardown := setupTest(t)
	defer teardown()

	// The private node should have the public node as a private peer
	addrs, err := state.ListPeerPrivateRPCAddresses(context.Background(), privateNode)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 {
		t.Errorf("expected 1 address, got %d", len(addrs))
	}
	for id, addr := range addrs {
		if id != publicNode {
			t.Errorf("expected peer id %s, got %s", publicNode, id)
		}
		if addr.String() != "172.16.0.1:1" {
			t.Errorf("expected '172.16.0.1:1', got %s", addr)
		}
	}

	// Reverse for the public node
	addrs, err = state.ListPeerPrivateRPCAddresses(context.Background(), publicNode)
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 {
		t.Errorf("expected 1 address, got %d", len(addrs))
	}
	for id, addr := range addrs {
		if id != privateNode {
			t.Errorf("expected peer id %s, got %s", privateNode, id)
		}
		if addr.String() != "172.16.0.2:1" {
			t.Errorf("expected '172.16.0.2:1', got %s", addr)
		}
	}
}

func setupTest(t *testing.T) (*state, func()) {
	t.Helper()
	db, err := nutsdb.New(nutsdb.Options{InMemory: true})
	if err != nil {
		t.Fatalf("create test db: %v", err)
	}
	close := func() {
		err := db.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	err = db.PutValue(ctx, IPv6PrefixKey, ipv6Prefix, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = db.PutValue(ctx, IPv4PrefixKey, ipv4Prefix, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = db.PutValue(ctx, MeshDomainKey, domain, 0)
	if err != nil {
		t.Fatal(err)
	}
	p := peers.New(db)
	// Node with public address
	err = p.Put(ctx, peers.Node{
		ID:              publicNode,
		PublicKey:       mustGenerateKey(t),
		PrimaryEndpoint: publicNodePublicAddr,
		GRPCPort:        rpcPort,
		RaftPort:        2,
		PrivateIPv4:     netip.MustParsePrefix(publicNodePrivateAddr),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Node with private address
	err = p.Put(ctx, peers.Node{
		ID:          privateNode,
		PublicKey:   mustGenerateKey(t),
		GRPCPort:    rpcPort,
		RaftPort:    2,
		PrivateIPv4: netip.MustParsePrefix(privateNodePrivateAddr),
	})
	if err != nil {
		t.Fatal(err)
	}
	s := New(db)
	return s.(*state), close
}

func mustGenerateKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key.PublicKey()
}
