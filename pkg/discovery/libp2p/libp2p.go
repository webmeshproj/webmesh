//go:build !wasm

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

// Package libp2p provides discovery mechanisms using Kademlia DHT.
package libp2p

import (
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
)

// JoinProtocol is the protocol used for joining a mesh.
const JoinProtocol = protocol.ID("/webmesh/join/0.0.1")

// KadDHTOptions are options for announcing the host or discovering peers
// on the libp2p kademlia DHT.
type KadDHTOptions struct {
	// PSK is the pre-shared key to use as a rendezvous point for the DHT.
	PSK string
	// BootstrapPeers is a list of bootstrap peers to use for the DHT.
	// If empty or nil, the default bootstrap peers will be used.
	BootstrapPeers []multiaddr.Multiaddr
	// Options are options for configuring the libp2p host.
	Options []libp2p.Option
	// DiscoveryTTL is the TTL to use for the discovery service.
	// This is only applicable when announcing the host.
	DiscoveryTTL time.Duration
}
