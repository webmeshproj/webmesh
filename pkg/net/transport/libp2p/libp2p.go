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

// Package libp2p provides webmesh integration with libp2p.
package libp2p

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/net/system/buffers"
)

const (
	// BootstrapProtocol is the protocol used for bootstrapping a mesh.
	BootstrapProtocol = protocol.ID("/webmesh/bootstrap/0.0.1")
	// RPCProtocol is the protocol used for executing RPCs against a mesh.
	// The method should be appended to the end of the protocol.
	RPCProtocol = protocol.ID("/webmesh/rpc/0.0.1")
	// RaftProtocol is the protocol used for webmesh raft.
	// This is not used yet.
	RaftProtocol = protocol.ID("/webmesh/raft/0.0.1")
	// UDPRelayProtocol is the protocol used for relaying UDP packets.
	// The destination node should be appended to the end of the protocol.
	UDPRelayProtocol = protocol.ID("/webmesh/udp-relay/0.0.1")
)

// NativeIdentity turns the given crypto.PrivateKey into a native ed25519 identity.
// This is used for mesh discovery mechanisms and is not compatible with the larger
// webmesh transport.
func NativeIdentity(key crypto.PrivateKey) libp2p.Option {
	wgkey, ok := key.(*crypto.WireGuardKey)
	if !ok {
		// Caller's fault
		panic(fmt.Errorf("native identity requires a wireguard key"))
	}
	id, err := wgkey.ToNativeIdentity()
	if err != nil {
		// This should never happen, it's a valid key.
		panic(fmt.Errorf("wireguard key to native identity: %w", err))
	}
	return libp2p.Identity(id)
}

// RPCProtocolFor returns the RPCProtocol for the given method.
func RPCProtocolFor(method string) protocol.ID {
	return protocol.ID(fmt.Sprintf("%s/%s", RPCProtocol, strings.TrimPrefix(method, "/")))
}

// UDPRelayProtocolFor returns the UDPRelayProtocol for accepting connections
// from the given public key.
func UDPRelayProtocolFor(pubkey crypto.PublicKey) protocol.ID {
	return protocol.ID(fmt.Sprintf("%s/%s", UDPRelayProtocol, pubkey.WireGuardKey().String()))
}

var buffersOnce sync.Once

// MaxBuffer is the maximum buffer size for libp2p.
const MaxBuffer = 2500000

// SetMaxSystemBuffers sets the system buffers to the maximum size for libp2p.
func SetMaxSystemBuffers() {
	SetSystemBuffers(MaxBuffer)
}

// SetSystemBuffers sets the system buffers to use for libp2p.
func SetSystemBuffers(size int) {
	buffersOnce.Do(func() {
		err := buffers.SetMaximumReadBuffer(size)
		if err != nil {
			slog.Default().Warn("Failed to set maximum read buffer", "error", err.Error())
		}
		err = buffers.SetMaximumWriteBuffer(size)
		if err != nil {
			slog.Default().Warn("Failed to set maximum write buffer", "error", err.Error())
		}
	})
}
