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

package testutil

import (
	"context"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshnet"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/meshnet/wireguard"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// PeerManager is a mock peer manager for wireguard.
type PeerManager struct {
	wg wireguard.Interface
}

// AddPeer adds a peer to the wireguard interface. IceServers is optional
// and provides a hint of mesh nodes that provide WebRTC signaling if
// required.
func (p *PeerManager) Add(ctx context.Context, peer *v1.WireGuardPeer, iceServers []string) error {
	key, err := crypto.DecodePublicKey(peer.GetNode().GetPublicKey())
	if err != nil {
		return err
	}
	return p.wg.PutPeer(ctx, &wireguard.Peer{
		ID:        peer.GetNode().GetId(),
		PublicKey: key,
	})
}

// RefreshPeers walks all peers against the provided list and makes sure
// they are up to date.
func (p *PeerManager) Refresh(ctx context.Context, peers []*v1.WireGuardPeer) error {
	seen := make(map[string]bool)
	for id := range p.wg.Peers() {
		seen[id] = false
		for _, p := range peers {
			if p.GetNode().GetId() == id {
				seen[id] = true
				break
			}
		}
		if !seen[id] {
			err := p.wg.DeletePeer(ctx, id)
			if err != nil {
				return err
			}
		}
	}
	for _, peer := range peers {
		err := p.Add(ctx, peer, nil)
		if err != nil {
			return err
		}
	}
	return nil
}

// Sync is like refresh but uses the storage to get the list of peers.
func (p *PeerManager) Sync(ctx context.Context) error {
	return nil
}

// Resolver returns a resolver backed by the storage
// of this instance.
func (p *PeerManager) Resolver() meshnet.PeerResolver {
	return &PeerResolver{}
}

// PeerResolver is a mock peer resolver for wireguard.
type PeerResolver struct{}

// NodeIDResolver returns a resolver that resolves node addresses by node ID.
func (p *PeerResolver) NodeIDResolver() transport.NodeIDResolver {
	return transport.NewNoopResolver[types.NodeID]()
}

// FeatureResolver returns a resolver that resolves node addresses by feature.
func (p *PeerResolver) FeatureResolver(filterFn ...meshnet.PeerFilterFunc) transport.FeatureResolver {
	return transport.NewNoopResolver[v1.Feature]()
}
