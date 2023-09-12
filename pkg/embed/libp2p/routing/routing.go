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

// Package routing implements the PeerRouting interface by computing the
// remote peer's wireguard address from its public key.
package routing

import (
	"context"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"

	p2putil "github.com/webmeshproj/webmesh/pkg/embed/libp2p/util"
	"github.com/webmeshproj/webmesh/pkg/util/netutil"
)

// PublicKeyRouter is a PeerRouting implementation that computes the remote
// peer's wireguard address from its public key.
var PublicKeyRouter = func(host.Host) (routing.PeerRouting, error) {
	return FindPeerFunc(FindPeer), nil
}

// FindPeerFunc wraps a function and implements the PeerRouting interface.
type FindPeerFunc func(ctx context.Context, id peer.ID) (peer.AddrInfo, error)

// FindPeer implements the PeerRouting interface.
func (f FindPeerFunc) FindPeer(ctx context.Context, id peer.ID) (peer.AddrInfo, error) {
	return f(ctx, id)
}

// FindPeer computes the remote peer's wireguard address from its public key.
// It assumes the port used for endpoint signaling in the returned results.
func FindPeer(ctx context.Context, id peer.ID) (peer.AddrInfo, error) {
	// Extract the public key from the peer ID.
	pubkey, err := p2putil.ExtractWebmeshPublicKey(ctx, id)
	if err != nil {
		return peer.AddrInfo{}, err
	}
	// We can compute a ULA and Local prefix from the public key.
	_, addr := netutil.GenerateULAWithKey(pubkey)
	return peer.AddrInfo{
		ID:    id,
		Addrs: p2putil.AddrToSignalMultiaddrs(addr),
	}, nil
}
