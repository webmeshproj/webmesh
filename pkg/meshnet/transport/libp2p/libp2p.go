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

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system/buffers"
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

// Host is an interface that provides facilities for connecting to peers over libp2p.
type Host interface {
	// ID returns the peer ID of the host.
	ID() peer.ID
	// Host is the underlying libp2p host.
	Host() host.Host
	// Close closes the host and its DHT.
	Close(ctx context.Context) error
}

// NewHost creates a new libp2p host with the given options.
func NewHost(ctx context.Context, opts HostOptions) (Host, error) {
	SetMaxSystemBuffers()
	if len(opts.LocalAddrs) > 0 {
		opts.Options = append(opts.Options, libp2p.ListenAddrs(opts.LocalAddrs...))
	}
	if opts.ConnectTimeout > 0 {
		opts.Options = append(opts.Options, libp2p.WithDialTimeout(opts.ConnectTimeout))
	}
	opts.Options = append(opts.Options, libp2p.FallbackDefaults)
	host, err := libp2p.New(opts.Options...)
	if err != nil {
		return nil, fmt.Errorf("new libp2p host: %w", err)
	}
	return wrapHost(host), nil
}

type libp2pHost struct {
	host host.Host
}

// wrapHost wraps a libp2p host.
func wrapHost(host host.Host) Host {
	return &libp2pHost{host}
}

// ID returns the peer ID of the host.
func (h *libp2pHost) ID() peer.ID {
	return h.host.ID()
}

// Host returns the underlying libp2p host.
func (h *libp2pHost) Host() host.Host {
	return h.host
}

// Close closes the host and shuts down all listeners.
func (h *libp2pHost) Close(ctx context.Context) error {
	return h.host.Close()
}
