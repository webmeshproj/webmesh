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
	"encoding/json"
	"fmt"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/config"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// DiscoveryHost is an interface that provides facilities for discovering and connecting
// to peers over libp2p. It can be used to avoid the need for re-creating a libp2p
// host and bootstrapping the DHT for each new connection.
type DiscoveryHost interface {
	// ID returns the peer ID of the host.
	ID() peer.ID
	// Host is the underlying libp2p host.
	Host() host.Host
	// DHT is the underlying libp2p DHT.
	DHT() *dht.IpfsDHT
	// Announce announces the host to the DHT for the given rendezvous string.
	Announce(ctx context.Context, rendezvous string, ttl time.Duration)
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

// MarshalJSON implements json.Marshaler.
func (o HostOptions) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"bootstrapPeers": o.BootstrapPeers,
		"options":        o.Options,
		"localAddrs":     o.LocalAddrs,
	})
}

// NewDiscoveryHost creates a new libp2p host connected to the DHT with the given options.
func NewDiscoveryHost(ctx context.Context, opts HostOptions) (DiscoveryHost, error) {
	host, err := NewHost(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("new libp2p host: %w", err)
	}
	dht, err := NewDHT(ctx, host.Host(), opts.BootstrapPeers, opts.ConnectTimeout)
	if err != nil {
		defer host.Close(ctx)
		return nil, fmt.Errorf("new libp2p host: %w", err)
	}
	return &discoveryHost{
		h:   host,
		dht: dht,
	}, nil
}

// WrapHostWithDiscovery will wrap a native libp2p Host, bootstrap a DHT alongside it and return a DiscoveryHost.
func WrapHostWithDiscovery(ctx context.Context, host Host, bootstrapPeers []multiaddr.Multiaddr, connectTimeout time.Duration) (DiscoveryHost, error) {
	dht, err := NewDHT(ctx, host.Host(), bootstrapPeers, connectTimeout)
	if err != nil {
		defer host.Close(ctx)
		return nil, fmt.Errorf("new libp2p host: %w", err)
	}
	return &discoveryHost{
		h:   host,
		dht: dht,
	}, nil
}

type discoveryHost struct {
	h   Host
	dht *dht.IpfsDHT
}

func (h *discoveryHost) ID() peer.ID {
	return h.h.ID()
}

func (h *discoveryHost) Host() host.Host {
	return h.h.Host()
}

func (h *discoveryHost) DHT() *dht.IpfsDHT {
	return h.dht
}

func (h *discoveryHost) Announce(ctx context.Context, rendezvous string, ttl time.Duration) {
	routingDiscovery := drouting.NewRoutingDiscovery(h.dht)
	var discoveryOpts []discovery.Option
	if ttl > 0 {
		discoveryOpts = append(discoveryOpts, discovery.TTL(ttl))
	}
	dutil.Advertise(ctx, routingDiscovery, rendezvous, discoveryOpts...)
}

func (h *discoveryHost) Close(ctx context.Context) error {
	if err := h.dht.Close(); err != nil {
		context.LoggerFrom(ctx).Error("Error shutting down DHT", "error", err.Error())
	}
	return h.h.Close(ctx)
}
