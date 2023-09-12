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

// Package wgtransport implements a WireGuard transport for libp2p.
package wgtransport

import (
	"io"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/pnet"
	"github.com/libp2p/go-libp2p/core/transport"
	"github.com/libp2p/go-libp2p/p2p/transport/quicreuse"
)

// Transport is the webmesh wireguard transport. This transport does not run a
// full mesh node, but rather utilizes libp2p streams to perform an authenticated
// keypair negotiation to compute IPv6 addresses for peers.
type Transport interface {
	// Closer for the underlying transport that shuts down the webmesh node.
	io.Closer
	// Transport is the underlying libp2p Transport.
	transport.Transport
	// Resolver is a resolver that uses knowledge of local peers to resolve addresses.
	transport.Resolver
}

// Constructor
type Constructor func(tu transport.Upgrader, host host.Host, key crypto.PrivKey, psk pnet.PSK, connManager *quicreuse.ConnManager, gater connmgr.ConnectionGater, rcmgr network.ResourceManager) (Transport, error)
