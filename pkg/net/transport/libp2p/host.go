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

package libp2p

import (
	"fmt"
	"io"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/config"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
)

// Host is an interface that provides facilities for discovering and connecting to
// peers over libp2p. It can be used to avoid the need for re-creating a libp2p
// host and bootstrapping the DHT for each new connection.
type Host interface {
	// ID returns the peer ID of the host.
	ID() peer.ID
	// Host is the underlying libp2p host.
	Host() host.Host
	// DHT is the underlying libp2p DHT.
	DHT() *dht.IpfsDHT
	// DataChannelAnnouncer returns a new data channel announcer using this host.
	DataChannelAnnouncer(ctx context.Context, opts DataChannelAnnounceOptions) *DataChannelAnnouncer
	// JoinAnnouncer returns a new join announcer using this host.
	JoinAnnouncer(ctx context.Context, opts JoinAnnounceOptions, rt transport.JoinServer) io.Closer
	// JoinRoundTripper returns a round tripper for executing a join request.
	JoinRoundTripper(ctx context.Context, opts RoundTripOptions) transport.JoinRoundTripper
	// Close closes the host and its DHT.
	Close(ctx context.Context) error
}

// HostOptions are options for creating a new libp2p host.
type HostOptions struct {
	// BootstrapPeers is a list of bootstrap peers to use for the DHT.
	// If empty or nil, the default bootstrap peers will be used.
	BootstrapPeers []multiaddr.Multiaddr
	// Options are options for configuring the libp2p host.
	Options []config.Option
	// LocalAddrs is a list of local addresses to announce the host with.
	// If empty or nil, the default local addresses will be used.
	LocalAddrs []multiaddr.Multiaddr
	// ConnectTimeout is the timeout for connecting to peers when bootstrapping.
	ConnectTimeout time.Duration
}

// NewHost creates a new libp2p host with the given options.
func NewHost(ctx context.Context, opts HostOptions) (Host, error) {
	SetBuffers(ctx)
	if len(opts.LocalAddrs) > 0 {
		opts.Options = append(opts.Options, libp2p.ListenAddrs(opts.LocalAddrs...))
	}
	host, err := libp2p.New(opts.Options...)
	if err != nil {
		return nil, fmt.Errorf("new libp2p host: %w", err)
	}
	dht, err := NewDHT(ctx, host, opts.BootstrapPeers, opts.ConnectTimeout)
	if err != nil {
		defer host.Close()
		return nil, fmt.Errorf("new libp2p host: %w", err)
	}
	return &libp2pHost{
		host: host,
		dht:  dht,
	}, nil
}

type libp2pHost struct {
	host host.Host
	dht  *dht.IpfsDHT
}

// ID returns the peer ID of the host.
func (h *libp2pHost) ID() peer.ID {
	return h.host.ID()
}

// Host returns the underlying libp2p host.
func (h *libp2pHost) Host() host.Host {
	return h.host
}

func (h *libp2pHost) DHT() *dht.IpfsDHT {
	return h.dht
}

func (h *libp2pHost) DataChannelAnnouncer(ctx context.Context, opts DataChannelAnnounceOptions) *DataChannelAnnouncer {
	return NewDataChannelAnnouncerWithHost(ctx, h, opts)
}

func (h *libp2pHost) JoinAnnouncer(ctx context.Context, opts JoinAnnounceOptions, rt transport.JoinServer) io.Closer {
	return NewJoinAnnouncerWithHost(ctx, h, opts, rt)
}

func (h *libp2pHost) JoinRoundTripper(ctx context.Context, opts RoundTripOptions) transport.JoinRoundTripper {
	return NewJoinRoundTripperWithHost(h, opts)
}

func (h *libp2pHost) Close(ctx context.Context) error {
	if err := h.dht.Close(); err != nil {
		context.LoggerFrom(ctx).Error("Error shutting down DHT", "error", err.Error())
	}
	return h.host.Close()
}
