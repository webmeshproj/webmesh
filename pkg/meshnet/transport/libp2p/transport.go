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
	"log/slog"
	"net"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/multiformats/go-multiaddr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
)

// TransportOptions are options for configuring an RPC transport over libp2p.
type TransportOptions struct {
	// Rendezvous is the pre-shared string to use as a rendezvous point for the DHT.
	Rendezvous string
	// HostOptions are options for configuring the host. These can be left
	// empty if using a pre-created host.
	HostOptions HostOptions
	// Host is a pre-started host to use for the transport.
	Host host.Host
	// Credentials are the credentials to use for the transport.
	Credentials []grpc.DialOption
}

// NewTransport returns a new transport using the underlying host. The passed addresses to Dial
// are parsed as a multiaddrs. It assumes the host's peerstore has been populated with the
// addresses before calls to Dial.
func NewTransport(host Host, credentials ...grpc.DialOption) transport.RPCTransport {
	// If no credentials are provided, default to insecure credentials.
	if len(credentials) == 0 {
		credentials = []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	}
	return &rpcTransport{h: host, creds: credentials}
}

// NewDiscoveryTransport returns a new RPC transport over libp2p using the IPFS DHT for discovery.
func NewDiscoveryTransport(ctx context.Context, opts TransportOptions) (transport.RPCTransport, error) {
	var h DiscoveryHost
	var err error
	var close func()
	if opts.Host != nil {
		host := wrapHost(opts.Host)
		dht, err := NewDHT(ctx, host.Host(), opts.HostOptions.BootstrapPeers, opts.HostOptions.ConnectTimeout)
		if err != nil {
			return nil, err
		}
		h = &discoveryHost{
			h:   host,
			dht: dht,
		}
		close = func() {
			err := dht.Close()
			if err != nil {
				context.LoggerFrom(ctx).Error("Failed to close DHT", "error", err.Error())
			}
		}
	} else {
		h, err = NewDiscoveryHost(ctx, opts.HostOptions)
		if err != nil {
			return nil, err
		}
		close = func() {
			err := h.Close(ctx)
			if err != nil {
				context.LoggerFrom(ctx).Error("Failed to close host", "error", err.Error())
			}
		}
	}
	return &rpcDiscoveryTransport{TransportOptions: opts, host: h, close: close}, nil
}

type rpcDiscoveryTransport struct {
	TransportOptions
	host  DiscoveryHost
	close func()
}

func (r *rpcDiscoveryTransport) Dial(ctx context.Context, _, _ string) (*grpc.ClientConn, error) {
	log := context.LoggerFrom(ctx).With(slog.String("host-id", r.host.Host().ID().String()))
	ctx = context.WithLogger(ctx, log)
	rt := NewTransport(r.host, r.Credentials...)
	log.Debug("Searching for peers on the DHT with our PSK", slog.String("psk", r.Rendezvous))
	routingDiscovery := drouting.NewRoutingDiscovery(r.host.DHT())
	peerChan, err := routingDiscovery.FindPeers(ctx, r.Rendezvous)
	if err != nil {
		return nil, fmt.Errorf("libp2p find peers: %w", err)
	}
	// Wait for a peer to connect to
	log.Debug("Waiting for peer to establish connection with")
SearchPeers:
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("no peers found to dial: %w", ctx.Err())
		case peer, ok := <-peerChan:
			if !ok {
				if ctx.Err() != nil {
					return nil, fmt.Errorf("no peers found to dial: %w", ctx.Err())
				}
				peerChan, err = routingDiscovery.FindPeers(ctx, r.Rendezvous)
				if err != nil {
					return nil, fmt.Errorf("libp2p find peers: %w", err)
				}
				continue SearchPeers
			}
			// Ignore ourselves and hosts with no addresses.
			jlog := log.With(slog.String("peer-id", peer.ID.String()), slog.Any("peer-addrs", peer.Addrs))
			if peer.ID == r.host.Host().ID() || len(peer.Addrs) == 0 {
				jlog.Debug("Ignoring peer")
				continue
			}
			for _, addr := range peer.Addrs {
				jlog.Debug("Dialing peer", slog.String("address", addr.String()))
				var connCtx context.Context
				var cancel context.CancelFunc
				if r.HostOptions.ConnectTimeout > 0 {
					connCtx, cancel = context.WithTimeout(ctx, r.HostOptions.ConnectTimeout)
				} else {
					connCtx, cancel = context.WithCancel(ctx)
				}
				c, err := rt.Dial(connCtx, string(peer.ID), addr.String())
				cancel()
				if err == nil {
					return c, nil
				}
				jlog.Debug("Failed to dial peer", "error", err)
			}
		}
	}
}

func (r *rpcDiscoveryTransport) Close() error {
	r.close()
	return nil
}

type rpcTransport struct {
	h     Host
	creds []grpc.DialOption
}

func (r *rpcTransport) Dial(ctx context.Context, id, address string) (*grpc.ClientConn, error) {
	pid := peer.ID(id)
	// Fastpath if we are using an uncertified peer store. We can add the address
	// to the peerstore and dial directly. This saves the caller some work.
	if _, ok := r.h.Host().Peerstore().(*UncertifiedPeerstore); ok && id != "" {
		// Try to find the peer with the given address.
		ma, err := multiaddr.NewMultiaddr(address)
		if err != nil {
			return nil, fmt.Errorf("parse multiaddr: %w", err)
		}
		r.h.Host().Peerstore().AddAddr(pid, ma, peerstore.PermanentAddrTTL)
		stream, err := r.h.Host().NewStream(ctx, pid, RPCProtocol)
		if err != nil {
			return nil, fmt.Errorf("new stream: %w", err)
		}
		return grpc.DialContext(ctx, "", append(r.creds, grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			return NewConnFromStream(stream), nil
		}))...)
	}
	// Next if we don't have an address but have an id, just dial the peer and
	// let the peerstore handle the rest.
	if address == "" && id != "" {
		stream, err := r.h.Host().NewStream(ctx, pid, RPCProtocol)
		if err != nil {
			return nil, fmt.Errorf("new stream: %w", err)
		}
		return grpc.DialContext(ctx, "", append(r.creds, grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			return NewConnFromStream(stream), nil
		}))...)
	}
	// Try to find the peer with the given address.
	ma, err := multiaddr.NewMultiaddr(address)
	if err != nil {
		return nil, fmt.Errorf("parse multiaddr: %w", err)
	}
	peers := r.h.Host().Peerstore().PeersWithAddrs()
	for _, pid := range peers {
		addrs := r.h.Host().Peerstore().Addrs(pid)
		for _, addr := range addrs {
			if !addr.Equal(ma) {
				continue
			}
			stream, err := r.h.Host().NewStream(ctx, pid, RPCProtocol)
			if err != nil {
				return nil, fmt.Errorf("new stream: %w", err)
			}
			return grpc.DialContext(ctx, "", append(r.creds, grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
				return NewConnFromStream(stream), nil
			}))...)
		}
	}
	return nil, fmt.Errorf("no peer found to dial with id %q and address %q", pid.String(), address)
}
