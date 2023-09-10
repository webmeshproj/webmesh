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

package peerstore

import (
	"context"
	"crypto/rand"
	"os"
	"strconv"
	"testing"
	"time"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/record"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/util"
	"github.com/webmeshproj/webmesh/pkg/util/logutil"
)

func TestPeerstore(t *testing.T) {
	// Test general behavior of the peerstore.
	t.Parallel()

	var (
		TestPeerKey         = crypto.MustGenerateKey()
		TestPeerID1 peer.ID = TestPeerKey.ID()
		TestPeerID2 peer.ID = crypto.MustGenerateKey().ID()
		TestPeerID3 peer.ID = crypto.MustGenerateKey().ID()
		TestPeerID4 peer.ID = crypto.MustGenerateKey().ID()

		TestAddr1 = ma.StringCast("/ip4/127.0.0.1/tcp/1234")
		TestAddr2 = ma.StringCast("/ip6/::1/tcp/1234")
		TestAddr3 = ma.StringCast("/dns4/localhost/tcp/1234")
		TestAddr4 = ma.StringCast("/dns6/localhost/tcp/1234")
	)

	t.Run("GetPeerInfo", func(t *testing.T) {
		// Place a peer and some addresses, they should come back in the addr info
		ps := setupTest(t)
		ps.AddAddrs(TestPeerID1, []ma.Multiaddr{TestAddr1, TestAddr2, TestAddr3, TestAddr4}, peerstore.PermanentAddrTTL)
		pi := ps.PeerInfo(TestPeerID1)
		if pi.ID != TestPeerID1 {
			t.Fatalf("expected peer info to have ID %s, got %s", TestPeerID1, pi.ID)
		}
		if len(pi.Addrs) != 4 {
			t.Fatalf("expected peer info to have 4 addresses, got %d", len(pi.Addrs))
		}
		for _, addr := range pi.Addrs {
			if addr.String() != TestAddr1.String() && addr.String() != TestAddr2.String() && addr.String() != TestAddr3.String() && addr.String() != TestAddr4.String() {
				t.Fatalf("expected peer info to have address %s, %s, %s or %s, got %s", TestAddr1, TestAddr2, TestAddr3, TestAddr4, addr)
			}
		}
	})

	t.Run("Peers", func(t *testing.T) {
		// Place all the peers and all the addreses. Make sure we get a full peer list back
		ps := setupTest(t)
		ps.AddAddrs(TestPeerID1, []ma.Multiaddr{TestAddr1, TestAddr2}, peerstore.PermanentAddrTTL)
		ps.AddAddrs(TestPeerID2, []ma.Multiaddr{TestAddr3, TestAddr4}, peerstore.PermanentAddrTTL)
		ps.AddAddrs(TestPeerID3, []ma.Multiaddr{TestAddr1, TestAddr4}, peerstore.PermanentAddrTTL)
		ps.AddAddrs(TestPeerID4, []ma.Multiaddr{TestAddr2, TestAddr3}, peerstore.PermanentAddrTTL)
		peers := ps.Peers()
		if len(peers) != 4 {
			t.Fatalf("expected peerstore to have 4 peers, got %d", len(peers))
		}
		for _, pr := range peers {
			if !util.Contains([]peer.ID{TestPeerID1, TestPeerID2, TestPeerID3, TestPeerID4}, pr) {
				t.Fatalf("expected peerstore to have peer %s", pr)
			}
		}
	})

	t.Run("RemovePeer", func(t *testing.T) {
		// Place data for a peer in all the buckets. Make sure they all get cleaned.
		ps := setupTest(t)
		ps.AddAddrs(TestPeerID1, []ma.Multiaddr{TestAddr1, TestAddr2}, peerstore.PermanentAddrTTL)
		err := ps.AddPrivKey(TestPeerID1, TestPeerKey)
		if err != nil {
			t.Fatal(err)
		}
		err = ps.AddPubKey(TestPeerID1, TestPeerKey.GetPublic())
		if err != nil {
			t.Fatal(err)
		}
		err = ps.AddProtocols(TestPeerID1, []protocol.ID{"/test/1.0.0", "/test/2.0.0"}...)
		if err != nil {
			t.Fatal(err)
		}
		ps.RecordLatency(TestPeerID1, time.Second)

		// We should validate all the data is there, but this whole suite would
		// be busted if that were not the case. Just make sure the peer is there.
		pi := ps.PeerInfo(TestPeerID1)
		if pi.ID != TestPeerID1 {
			t.Fatalf("expected peer info to have ID %s, got %s", TestPeerID1, pi.ID)
		}
		peers := ps.Peers()
		if len(peers) != 1 {
			t.Fatalf("expected peerstore to have 1 peer, got %d", len(peers))
		}
		if peers[0] != TestPeerID1 {
			t.Fatalf("expected peerstore to have peer %s", TestPeerID1)
		}

		ps.RemovePeer(TestPeerID1)

		// Make sure all the data is gone
		pi = ps.PeerInfo(TestPeerID1)
		if len(pi.Addrs) != 0 {
			t.Fatalf("expected peer info to have 0 addresses, got %d", len(pi.Addrs))
		}
		addrs := ps.Addrs(TestPeerID1)
		if len(addrs) != 0 {
			t.Fatalf("expected peer to have 0 addresses, got %d", len(addrs))
		}
		privkey := ps.PrivKey(TestPeerID1)
		if privkey != nil {
			t.Fatalf("expected peer to have no private key, got %s", privkey)
		}
		pubkey := ps.PubKey(TestPeerID1)
		if pubkey != nil {
			t.Fatalf("expected peer to have no public key, got %s", pubkey)
		}
		protocols, err := ps.GetProtocols(TestPeerID1)
		if err != nil {
			t.Fatal(err)
		}
		if len(protocols) != 0 {
			t.Fatalf("expected peer to have no protocols, got %d", len(protocols))
		}
		latency := ps.LatencyEWMA(TestPeerID1)
		if latency != 0 {
			t.Fatalf("expected peer to have no latency, got %s", latency)
		}
	})
}

func TestCertifiedAddrBook(t *testing.T) {
	t.Parallel()

	var (
		TestPeerKey         = crypto.MustGenerateKey()
		TestPeerID  peer.ID = TestPeerKey.ID()

		TestAddr1 = ma.StringCast("/ip4/127.0.0.1/tcp/1234")
		TestAddr2 = ma.StringCast("/ip6/::1/tcp/1234")
		TestAddr3 = ma.StringCast("/dns4/localhost/tcp/1234")
		TestAddr4 = ma.StringCast("/dns6/localhost/tcp/1234")
	)

	t.Run("TestCertifiedAddrs", func(t *testing.T) {
		ps := setupTest(t)
		// Add all the addresses
		ps.AddAddrs(TestPeerID, []ma.Multiaddr{TestAddr1, TestAddr2, TestAddr3, TestAddr4}, peerstore.PermanentAddrTTL)
		// Make sure we get them all back
		addrs := ps.Addrs(TestPeerID)
		if len(addrs) != 4 {
			t.Fatalf("expected peer to have 4 addresses, got %d", len(addrs))
		}
		// Certify one of the addresses
		rec := &peer.PeerRecord{
			PeerID: TestPeerID,
			Addrs:  []ma.Multiaddr{TestAddr1},
			Seq:    1,
		}
		signed, err := record.Seal(rec, TestPeerKey)
		if err != nil {
			t.Fatal(err)
		}
		accepted, err := ps.ConsumePeerRecord(signed, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if !accepted {
			t.Fatal("expected record to be accepted")
		}
		// We should now only get 1 address back
		addrs = ps.Addrs(TestPeerID)
		if len(addrs) != 1 {
			t.Fatalf("expected peer to have 1 address, got %d", len(addrs))
		}
		if addrs[0].String() != TestAddr1.String() {
			t.Fatalf("expected peer to have address %s, got %s", TestAddr1, addrs[0])
		}
		// Try to place an envelope with a lower sequence number
		rec = &peer.PeerRecord{
			PeerID: TestPeerID,
			Addrs:  []ma.Multiaddr{TestAddr2},
			Seq:    0,
		}
		signed, err = record.Seal(rec, TestPeerKey)
		if err != nil {
			t.Fatal(err)
		}
		accepted, err = ps.ConsumePeerRecord(signed, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if accepted {
			t.Fatal("expected record to not be accepted")
		}
		// We should get the same addresses as before back
		addrs = ps.Addrs(TestPeerID)
		if len(addrs) != 1 {
			t.Fatalf("expected peer to have 1 address, got %d", len(addrs))
		}
		if addrs[0].String() != TestAddr1.String() {
			t.Fatalf("expected peer to have address %s, got %s", TestAddr1, addrs[0])
		}
		// Place a new envelope with the same sequence, it should replace the existing one
		rec = &peer.PeerRecord{
			PeerID: TestPeerID,
			Addrs:  []ma.Multiaddr{TestAddr1, TestAddr2},
			Seq:    1,
		}
		signed, err = record.Seal(rec, TestPeerKey)
		if err != nil {
			t.Fatal(err)
		}
		accepted, err = ps.ConsumePeerRecord(signed, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if !accepted {
			t.Fatal("expected record to be accepted")
		}
		// We should now get 2 addresses back
		addrs = ps.Addrs(TestPeerID)
		if len(addrs) != 2 {
			t.Fatalf("expected peer to have 2 addresses, got %d", len(addrs))
		}
		for _, addr := range addrs {
			if addr.String() != TestAddr1.String() && addr.String() != TestAddr2.String() {
				t.Fatalf("expected peer to have address %s or %s, got %s", TestAddr1, TestAddr2, addr)
			}
		}
		// Same test but with a higher sequence number
		rec = &peer.PeerRecord{
			PeerID: TestPeerID,
			Addrs:  []ma.Multiaddr{TestAddr3, TestAddr4},
			Seq:    3,
		}
		signed, err = record.Seal(rec, TestPeerKey)
		if err != nil {
			t.Fatal(err)
		}
		accepted, err = ps.ConsumePeerRecord(signed, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if !accepted {
			t.Fatal("expected record to be accepted")
		}
		// We should now get the other 2 addresses back
		addrs = ps.Addrs(TestPeerID)
		if len(addrs) != 2 {
			t.Fatalf("expected peer to have 2 addresses, got %d", len(addrs))
		}
		for _, addr := range addrs {
			if addr.String() != TestAddr3.String() && addr.String() != TestAddr4.String() {
				t.Fatalf("expected peer to have address %s or %s, got %s", TestAddr3, TestAddr4, addr)
			}
		}
	})
}

func TestAddrBook(t *testing.T) {
	t.Parallel()

	var (
		TestPeerID1 peer.ID = crypto.MustGenerateKey().ID()
		TestPeerID2 peer.ID = crypto.MustGenerateKey().ID()
		TestPeerID3 peer.ID = crypto.MustGenerateKey().ID()
		TestPeerID4 peer.ID = crypto.MustGenerateKey().ID()

		TestAddr1 = ma.StringCast("/ip4/127.0.0.1/tcp/1234")
		TestAddr2 = ma.StringCast("/ip6/::1/tcp/1234")
		TestAddr3 = ma.StringCast("/dns4/localhost/tcp/1234")
		TestAddr4 = ma.StringCast("/dns6/localhost/tcp/1234")
	)

	t.Run("AddAddrs", func(t *testing.T) {
		ps := setupTest(t)
		// Add an adress for a peer
		ps.AddAddr(TestPeerID1, TestAddr1, peerstore.PermanentAddrTTL)
		addrs := ps.Addrs(TestPeerID1)
		if len(addrs) != 1 {
			t.Fatalf("expected peer to have 1 address, got %d", len(addrs))
		}
		if addrs[0].String() != TestAddr1.String() {
			t.Fatalf("expected peer to have address %s, got %s", TestAddr1, addrs[0])
		}
		// Add an address with a TTL
		ps.SetAddrs(TestPeerID1, []ma.Multiaddr{TestAddr2}, time.Second*2)
		addrs = ps.Addrs(TestPeerID1)
		if len(addrs) != 2 {
			t.Fatalf("expected peer to have 2 addresses, got %d", len(addrs))
		}
		if addrs[1].String() != TestAddr2.String() {
			t.Fatalf("expected peer to have address %s, got %s", TestAddr2, addrs[1])
		}
		<-time.After(time.Second * 2)
		addrs = ps.Addrs(TestPeerID1)
		if len(addrs) != 1 {
			t.Fatalf("expected peer to have 1 address, got %d", len(addrs))
		}
		if addrs[0].String() != TestAddr1.String() {
			t.Fatalf("expected peer to have address %s, got %s", TestAddr1, addrs[0])
		}
	})

	t.Run("SetAddrs", func(t *testing.T) {
		ps := setupTest(t)
		// Set an address for a peer with a short TTL
		ps.SetAddr(TestPeerID1, TestAddr1, time.Second*2)
		addrs := ps.Addrs(TestPeerID1)
		if len(addrs) != 1 {
			t.Fatalf("expected peer to have 1 address, got %d", len(addrs))
		}
		if addrs[0].String() != TestAddr1.String() {
			t.Fatalf("expected peer to have address %s, got %s", TestAddr1, addrs[0])
		}
		// Try to update to a permanent address
		ps.SetAddrs(TestPeerID1, []ma.Multiaddr{TestAddr1}, peerstore.PermanentAddrTTL)
		addrs = ps.Addrs(TestPeerID1)
		if len(addrs) != 1 {
			t.Fatalf("expected peer to have 1 address, got %d", len(addrs))
		}
		if addrs[0].String() != TestAddr1.String() {
			t.Fatalf("expected peer to have address %s, got %s", TestAddr1, addrs[0])
		}
		// Make sure the peer is still there after the TTL
		<-time.After(time.Second * 2)
		addrs = ps.Addrs(TestPeerID1)
		if len(addrs) != 1 {
			t.Fatalf("expected peer to have 1 address, got %d", len(addrs))
		}
		if addrs[0].String() != TestAddr1.String() {
			t.Fatalf("expected peer to have address %s, got %s", TestAddr1, addrs[0])
		}
	})

	t.Run("UpdateAddrs", func(t *testing.T) {
		ps := setupTest(t)
		// Set an address for a peer with a short TTL
		ps.SetAddrs(TestPeerID1, []ma.Multiaddr{TestAddr1}, time.Second*2)
		addrs := ps.Addrs(TestPeerID1)
		if len(addrs) != 1 {
			t.Fatalf("expected peer to have 1 address, got %d", len(addrs))
		}
		if addrs[0].String() != TestAddr1.String() {
			t.Fatalf("expected peer to have address %s, got %s", TestAddr1, addrs[0])
		}
		// Update the address
		ps.UpdateAddrs(TestPeerID1, time.Second*2, peerstore.PermanentAddrTTL)
		addrs = ps.Addrs(TestPeerID1)
		if len(addrs) != 1 {
			t.Fatalf("expected peer to have 1 address, got %d", len(addrs))
		}
		if addrs[0].String() != TestAddr1.String() {
			t.Fatalf("expected peer to have address %s, got %s", TestAddr1, addrs[0])
		}
		// Make sure the peer is still there after the TTL
		<-time.After(time.Second * 2)
		addrs = ps.Addrs(TestPeerID1)
		if len(addrs) != 1 {
			t.Fatalf("expected peer to have 1 address, got %d", len(addrs))
		}
		if addrs[0].String() != TestAddr1.String() {
			t.Fatalf("expected peer to have address %s, got %s", TestAddr1, addrs[0])
		}
	})

	t.Run("AddrStream", func(t *testing.T) {
		t.Skip("Test is time sensitive")

		ps := setupTest(t)
		ctx, cancel := context.WithCancel(context.Background())
		stream := ps.AddrStream(ctx, TestPeerID1)
		seen := map[ma.Multiaddr]struct{}{}
		addrs := []ma.Multiaddr{TestAddr1, TestAddr2, TestAddr3, TestAddr4}
		ps.AddAddrs(TestPeerID1, addrs, peerstore.PermanentAddrTTL)
		<-time.After(time.Second * 5)
		cancel()
		for addr := range stream {
			seen[addr] = struct{}{}
		}
		if len(seen) != 4 {
			t.Fatalf("expected to see 4 addresses, got %d", len(seen))
		}
		t.Log("seen:", seen)
		noneEqual := func(a ma.Multiaddr, seen map[ma.Multiaddr]struct{}) bool {
			for addr := range seen {
				if a.Equal(addr) {
					return false
				}
			}
			return true
		}
		for _, addr := range addrs {
			if noneEqual(addr, seen) {
				t.Fatalf("expected to see address %s", addr)
			}
		}
	})

	t.Run("ClearAddrs", func(t *testing.T) {
		// Add a bunch of addresses for a peer
		ps := setupTest(t)
		ps.AddAddrs(TestPeerID1, []ma.Multiaddr{TestAddr1, TestAddr2, TestAddr3, TestAddr4}, peerstore.PermanentAddrTTL)
		addrs := ps.Addrs(TestPeerID1)
		if len(addrs) != 4 {
			t.Fatalf("expected peer to have 4 addresses, got %d", len(addrs))
		}
		// Clear the addresses
		ps.ClearAddrs(TestPeerID1)
		addrs = ps.Addrs(TestPeerID1)
		if len(addrs) != 0 {
			t.Fatalf("expected peer to have 0 addresses, got %d", len(addrs))
		}
	})

	t.Run("PeersWithAddrs", func(t *testing.T) {
		// Place addresses for a bunch of peers
		ps := setupTest(t)
		ps.AddAddrs(TestPeerID1, []ma.Multiaddr{TestAddr1, TestAddr2}, peerstore.PermanentAddrTTL)
		ps.AddAddrs(TestPeerID2, []ma.Multiaddr{TestAddr3, TestAddr4}, peerstore.PermanentAddrTTL)
		ps.AddAddrs(TestPeerID3, []ma.Multiaddr{TestAddr1, TestAddr3}, peerstore.PermanentAddrTTL)
		ps.AddAddrs(TestPeerID4, []ma.Multiaddr{TestAddr2, TestAddr4}, peerstore.PermanentAddrTTL)
		// Make sure we get all the peers back
		peers := ps.PeersWithAddrs()
		if len(peers) != 4 {
			t.Fatalf("expected to have 4 peers, got %d", len(peers))
		}
		// Make sure we get the right peers back
		expected := []peer.ID{TestPeerID1, TestPeerID2, TestPeerID3, TestPeerID4}
		for _, p := range peers {
			if !util.Contains(expected, p) {
				t.Fatalf("expected to have peer %s", p)
			}
		}
	})
}

func TestKeyBook(t *testing.T) {
	t.Parallel()

	// We'll generate inline keys in this test so we can verify them
	// against the ones in the key book.
	key1 := mustGenerateWireGuardKey(t)
	key2 := mustGenerateWireGuardKey(t)
	key3 := mustGenerateECDSAKey(t)
	key4 := mustGenerateECDSAKey(t)

	peerID1 := key1.ID()
	peerID2 := key2.ID()
	peerID3, err := peer.IDFromPrivateKey(key3)
	if err != nil {
		t.Fatal(err)
	}
	peerID4, err := peer.IDFromPrivateKey(key4)
	if err != nil {
		t.Fatal(err)
	}

	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}

	t.Run("GetAddPubKey", func(t *testing.T) {
		ps := setupTest(t)

		// Add all the keys and make sure we can get them back.
		must(ps.AddPubKey(peerID1, key1.GetPublic()))
		must(ps.AddPubKey(peerID2, key2.GetPublic()))
		must(ps.AddPubKey(peerID3, key3.GetPublic()))
		must(ps.AddPubKey(peerID4, key4.GetPublic()))
		// Make sure we can get the keys back
		k1 := ps.PubKey(peerID1)
		k2 := ps.PubKey(peerID2)
		k3 := ps.PubKey(peerID3)
		k4 := ps.PubKey(peerID4)

		if k1 == nil || k2 == nil || k3 == nil || k4 == nil {
			t.Fatal("expected to get keys back for all peers")
		}
		if !k1.Equals(key1.GetPublic()) {
			t.Fatalf("expected key %s, got %s", key1.GetPublic(), k1)
		}
		if !k2.Equals(key2.GetPublic()) {
			t.Fatalf("expected key %s, got %s", key2.GetPublic(), k2)
		}
		if !k3.Equals(key3.GetPublic()) {
			t.Fatalf("expected key %s, got %s", key3.GetPublic(), k3)
		}
		if !k4.Equals(key4.GetPublic()) {
			t.Fatalf("expected key %s, got %s", key4.GetPublic(), k4)
		}
	})

	t.Run("GetAddPrivKey", func(t *testing.T) {
		ps := setupTest(t)

		// Same test for public keys but with private keys.
		must(ps.AddPrivKey(peerID1, key1))
		must(ps.AddPrivKey(peerID2, key2))
		must(ps.AddPrivKey(peerID3, key3))
		must(ps.AddPrivKey(peerID4, key4))
		// Make sure we can get the keys back
		k1 := ps.PrivKey(peerID1)
		k2 := ps.PrivKey(peerID2)
		k3 := ps.PrivKey(peerID3)
		k4 := ps.PrivKey(peerID4)

		if k1 == nil || k2 == nil || k3 == nil || k4 == nil {
			t.Fatal("expected to get keys back for all peers")
		}
		if !k1.Equals(key1) {
			t.Fatalf("expected key %s, got %s", key1, k1)
		}
		if !k2.Equals(key2) {
			t.Fatalf("expected key %s, got %s", key2, k2)
		}
		if !k3.Equals(key3) {
			t.Fatalf("expected key %s, got %s", key3, k3)
		}
		if !k4.Equals(key4) {
			t.Fatalf("expected key %s, got %s", key4, k4)
		}
	})

	t.Run("PeersWithKeys", func(t *testing.T) {
		ps := setupTest(t)

		// Add all the keys and make sure we get the peers back
		must(ps.AddPubKey(peerID1, key1.GetPublic()))
		must(ps.AddPubKey(peerID2, key2.GetPublic()))
		must(ps.AddPubKey(peerID3, key3.GetPublic()))
		must(ps.AddPubKey(peerID4, key4.GetPublic()))

		peers := ps.PeersWithKeys()
		if len(peers) != 4 {
			t.Fatalf("expected to have 4 peers, got %d", len(peers))
		}
		expected := []peer.ID{peerID1, peerID2, peerID3, peerID4}
		for _, p := range peers {
			if !util.Contains(expected, p) {
				t.Fatalf("expected to have peer %s", p)
			}
		}
	})
}

func TestPeerProtocols(t *testing.T) {
	t.Parallel()

	const (
		TestIDProto      protocol.ID = "/id/1.0.0"
		TestSecProto     protocol.ID = "/sec/2.0.0"
		TestGenericProto protocol.ID = "/generic/3.0.0"
	)

	var TestPeer = crypto.MustGenerateKey().ID()
	var AllProtos = []protocol.ID{TestIDProto, TestSecProto, TestGenericProto}

	t.Run("AddAndGetProtocols", func(t *testing.T) {
		// Add all the protocols and make sure we get them back.
		ps := setupTest(t)
		err := ps.AddProtocols(TestPeer, AllProtos...)
		if err != nil {
			t.Fatal(err)
		}
		protos, err := ps.GetProtocols(TestPeer)
		if err != nil {
			t.Fatal(err)
		}
		if len(protos) != len(AllProtos) {
			t.Fatalf("expected to get %d protocols, got %d", len(AllProtos), len(protos))
		}
		for _, proto := range AllProtos {
			if !util.Contains(protos, proto) {
				t.Fatalf("expected to get protocol %s", proto)
			}
		}
	})

	t.Run("SetProtocols", func(t *testing.T) {
		// Add all the protocols and then set only one of them
		// and make sure we get only that one back.
		ps := setupTest(t)
		err := ps.AddProtocols(TestPeer, AllProtos...)
		if err != nil {
			t.Fatal(err)
		}
		err = ps.SetProtocols(TestPeer, TestIDProto)
		if err != nil {
			t.Fatal(err)
		}
		protos, err := ps.GetProtocols(TestPeer)
		if err != nil {
			t.Fatal(err)
		}
		if len(protos) != 1 {
			t.Fatalf("expected to get 1 protocol, got %d: %v", len(protos), protos)
		}
		if protos[0] != TestIDProto {
			t.Fatalf("expected to get protocol %s, got %s", TestIDProto, protos[0])
		}
	})

	t.Run("RemoveProtocols", func(t *testing.T) {
		// Add and then remove all of the protocols
		ps := setupTest(t)
		err := ps.AddProtocols(TestPeer, AllProtos...)
		if err != nil {
			t.Fatal(err)
		}
		err = ps.RemoveProtocols(TestPeer, AllProtos...)
		if err != nil {
			t.Fatal(err)
		}
		protos, err := ps.GetProtocols(TestPeer)
		if err != nil {
			t.Fatal(err)
		}
		if len(protos) != 0 {
			t.Fatalf("expected to get 0 protocols, got %d", len(protos))
		}
	})

	t.Run("SupportsProtocols", func(t *testing.T) {
		// Add all the protocols to the peer and make sure it supports them
		ps := setupTest(t)
		err := ps.AddProtocols(TestPeer, AllProtos...)
		if err != nil {
			t.Fatal(err)
		}
		protos, err := ps.SupportsProtocols(TestPeer, AllProtos...)
		if err != nil {
			t.Fatal(err)
		}
		if len(protos) != len(AllProtos) {
			t.Fatalf("expected to get %d protocols, got %d", len(AllProtos), len(protos))
		}
		for _, proto := range AllProtos {
			if !util.Contains(protos, proto) {
				t.Fatalf("expected to get protocol %s", proto)
			}
		}
		// Make sure we don't get anything for random protocols
		protos, err = ps.SupportsProtocols(TestPeer, "/random/1.0.0", "/random/2.0.0")
		if err != nil {
			t.Fatal(err)
		}
		if len(protos) != 0 {
			t.Fatalf("expected to get 0 protocols, got %d", len(protos))
		}
	})

	t.Run("FirstSupportedProtocol", func(t *testing.T) {
		// We should always see the first protocol in the list we pass back
		ps := setupTest(t)
		err := ps.AddProtocols(TestPeer, AllProtos...)
		if err != nil {
			t.Fatal(err)
		}
		// Simple test-case of only looking for one
		for _, proto := range AllProtos {
			p, err := ps.FirstSupportedProtocol(TestPeer, proto)
			if err != nil {
				t.Fatal(err)
			}
			if p != proto {
				t.Fatalf("expected to get protocol %s, got %s", proto, p)
			}
		}
		// Look for two protocols and make sure we always get the first one
		p, err := ps.FirstSupportedProtocol(TestPeer, TestIDProto, TestSecProto)
		if err != nil {
			t.Fatal(err)
		}
		if p != TestIDProto {
			t.Fatalf("expected to get protocol %s, got %s", TestIDProto, p)
		}
		p, err = ps.FirstSupportedProtocol(TestPeer, TestSecProto, TestIDProto)
		if err != nil {
			t.Fatal(err)
		}
		if p != TestSecProto {
			t.Fatalf("expected to get protocol %s, got %s", TestSecProto, p)
		}
		// Make sure we don't get anything for random protocols
		p, err = ps.FirstSupportedProtocol(TestPeer, "/random/1.0.0", "/random/2.0.0")
		if err != nil {
			t.Fatal(err)
		}
		if p != "" {
			t.Fatalf("expected to get empty protocol, got %s", p)
		}
	})
}

func TestPeerMetadata(t *testing.T) {
	t.Parallel()

	t.Run("GetAndPutMetadata", func(t *testing.T) {
		ps := setupTest(t)
		peer := mustGenerateWireGuardKey(t).ID()
		var meta = map[string]any{
			"foo": "bar",
			"baz": 123,
		}
		for k, v := range meta {
			err := ps.Put(peer, k, v)
			if err != nil {
				t.Fatal(err)
			}
		}
		for k, v := range meta {
			val, err := ps.Get(peer, k)
			if err != nil {
				t.Fatal(err)
			}
			if val != v {
				t.Fatalf("expected to get value %v, got %v", v, val)
			}
		}
	})

}

func TestPeerMetrics(t *testing.T) {
	t.Parallel()

	t.Run("PeerLatency", func(t *testing.T) {
		// Record a bunch of observations and make sure we get the right
		// average back
		ps := setupTest(t)
		peer := mustGenerateWireGuardKey(t).ID()
		latencies := []time.Duration{
			time.Millisecond * 100,
			time.Millisecond * 200,
			time.Millisecond * 300,
			time.Millisecond * 400,
			time.Millisecond * 500,
		}
		expectedAvg := time.Millisecond * 300
		for _, latency := range latencies {
			ps.RecordLatency(peer, latency)
		}
		avg := ps.LatencyEWMA(peer)
		if avg != expectedAvg {
			t.Fatalf("expected to get average %s, got %s", expectedAvg, avg)
		}
	})
}

func setupTest(t *testing.T) *Peerstore {
	t.Helper()
	// We set this to a high number by default to allow
	// multiple in-memory databases to work in parallel.
	// But we'll let a user override it if they want.
	numGoroutines := 128
	if os.Getenv("PEERSTORE_TEST_NUM_GOROUTINES") != "" {
		var err error
		numGoroutines, err = strconv.Atoi(os.Getenv("PEERSTORE_TEST_NUM_GOROUTINES"))
		if err != nil {
			t.Fatal(err)
		}
	}
	db := New(Options{
		Logger:        logutil.NewLogger("error"),
		EnableMetrics: false,
		NumGoroutines: numGoroutines,
	})
	t.Cleanup(func() {
		err := db.Close()
		if err != nil {
			t.Log("error closing database:", err)
		}
	})
	return db
}

func mustGenerateWireGuardKey(t *testing.T) crypto.PrivateKey {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustGenerateECDSAKey(t *testing.T) p2pcrypto.PrivKey {
	t.Helper()
	key, _, err := p2pcrypto.GenerateECDSAKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
