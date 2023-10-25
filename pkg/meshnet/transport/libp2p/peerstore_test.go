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

package libp2p

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/crypto"
)

func TestUncertifiedPeerstore(t *testing.T) {
	ps, err := NewUncertifiedPeerstore()
	if err != nil {
		t.Fatal(err)
	}
	// Make sure we can coerce it to a certified peerstore.
	// The certification methods should be no-ops.
	_, ok := peerstore.GetCertifiedAddrBook(ps)
	if !ok {
		t.Fatal("expected certified addr book")
	}
	// Make sure we can add addresses and have them immediately be
	// available.
	key := crypto.MustGenerateKey()
	id := key.ID()
	ps.AddAddrs(peer.ID(id), []multiaddr.Multiaddr{multiaddr.StringCast("/ip4/127.0.0.1/tcp/8080")}, peerstore.PermanentAddrTTL)
	addrs := ps.Addrs(peer.ID(id))
	if len(addrs) != 1 {
		t.Fatal("expected 1 address")
	}
	if addrs[0].String() != "/ip4/127.0.0.1/tcp/8080" {
		t.Errorf("unexpected address: %s", addrs[0])
	}
}
