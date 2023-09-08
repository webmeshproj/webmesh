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

// Package routing defines a PeerRouting interface for libp2p webmesh.
package routiing

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/libp2p/go-libp2p/config"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"
	"github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// PeerRoutingBuilder is the signature of a function that builds a PeerRouting instance.
type PeerRoutingBuilder config.RoutingC

// New returns a new PeerRoutingBuilder.
func New() PeerRoutingBuilder {
	return func(host host.Host) (routing.PeerRouting, error) {
		return &PeerRouting{
			host: host,
		}, nil
	}
}

// PeerRouting is a routing.PeerRouting implementation that uses the meshdb to find peers.
type PeerRouting struct {
	host    host.Host
	storage storage.MeshStorage
	mu      sync.Mutex
}

// ProvideStorage provides a storage instance to the peer routing.
func (rt *PeerRouting) ProvideStorage(storage storage.MeshStorage) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.storage = storage
}

// FindPeer searches for a peer with the given ID and returns its address.
func (rt *PeerRouting) FindPeer(ctx context.Context, peerID peer.ID) (peer.AddrInfo, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.storage == nil {
		return peer.AddrInfo{}, errors.New("storage not initialized")
	}
	// TODO: Check if we are looking up ourself.
	pubKey, err := crypto.ExtractPublicKey(peerID)
	if err != nil {
		return peer.AddrInfo{}, fmt.Errorf("failed to extract public key: %w", err)
	}
	node, err := peers.New(rt.storage).GetByHostKey(ctx, pubKey)
	if err != nil {
		return peer.AddrInfo{}, fmt.Errorf("failed to get peer: %w", err)
	}
	var addrs []multiaddr.Multiaddr
	for _, addr := range node.GetMultiaddrs() {
		a, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			return peer.AddrInfo{}, fmt.Errorf("failed to parse multiaddr: %w", err)
		}
		addrs = append(addrs, a)
	}
	return peer.AddrInfo{
		ID:    peerID,
		Addrs: addrs,
	}, nil
}
