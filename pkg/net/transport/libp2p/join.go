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
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"github.com/multiformats/go-multiaddr"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/proto"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/system/buffers"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
)

// DHTJoinOptions are options for joining a cluster with the libp2p kademlia DHT.
type DHTJoinOptions struct {
	// PSK is the pre-shared key to use as a rendezvous point for the DHT.
	PSK string
	// BootstrapPeers is a list of bootstrap peers to use for the DHT.
	// If empty or nil, the default bootstrap peers will be used.
	BootstrapPeers []multiaddr.Multiaddr
	// Options are options for configuring the libp2p host.
	Options []libp2p.Option
	// ConnectTimeout is the per-address timeout for connecting to a peer.
	ConnectTimeout time.Duration
}

// NewDHTJoinRoundTripper returns a round tripper that uses the libp2p kademlia DHT to join a cluster.
func NewDHTJoinRoundTripper(opts DHTJoinOptions) transport.JoinRoundTripper {
	return &dhtJoinRoundTripper{opts}
}

type dhtJoinRoundTripper struct {
	DHTJoinOptions
}

// RoundTrip executes a request to join a cluster.
func (rt *dhtJoinRoundTripper) RoundTrip(ctx context.Context, req *v1.JoinRequest) (*v1.JoinResponse, error) {
	log := context.LoggerFrom(ctx)
	// Try to set the maximum read and write buffer sizes.
	err := buffers.SetMaximumReadBuffer(2500000)
	if err != nil {
		log.Warn("Failed to set maximum read buffer", "error", err.Error())
	}
	err = buffers.SetMaximumWriteBuffer(2500000)
	if err != nil {
		log.Warn("Failed to set maximum write buffer", "error", err.Error())
	}
	// Create a new libp2p host.
	host, err := libp2p.New(rt.Options...)
	if err != nil {
		return nil, fmt.Errorf("libp2p new host: %w", err)
	}
	defer host.Close()
	log = log.With(slog.String("host-id", host.ID().String()))
	ctx = context.WithLogger(ctx, log)
	// Bootstrap the DHT.
	log.Debug("Bootstrapping DHT")
	kaddht, err := dht.New(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("libp2p new dht: %w", err)
	}
	defer kaddht.Close()
	err = bootstrapDHT(ctx, host, kaddht, rt.BootstrapPeers)
	if err != nil {
		return nil, fmt.Errorf("libp2p bootstrap dht: %w", err)
	}
	// Announce the join protocol with our PSK.
	log.Debug("Searching for peers on the DHT with our PSK")
	routingDiscovery := drouting.NewRoutingDiscovery(kaddht)
	peerChan, err := routingDiscovery.FindPeers(ctx, rt.PSK)
	if err != nil {
		return nil, fmt.Errorf("libp2p find peers: %w", err)
	}
	// Marshal the join request
	joinData, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal join request: %w", err)
	}
	// Wait for a peer to connect to
	log.Debug("Waiting for peer to establish connection with")
	for peer := range peerChan {
		// Ignore ourselves and hosts with no addresses.
		jlog := log.With(slog.String("peer-id", peer.ID.String()), slog.Any("peer-addrs", peer.Addrs))
		if peer.ID == host.ID() || len(peer.Addrs) == 0 {
			jlog.Debug("Ignoring peer")
			continue
		}
		jlog.Debug("Dialing peer")
		var joinCtx context.Context
		var cancel context.CancelFunc
		if rt.ConnectTimeout > 0 {
			joinCtx, cancel = context.WithTimeout(ctx, rt.ConnectTimeout)
		} else {
			joinCtx, cancel = context.WithCancel(ctx)
		}
		stream, err := host.NewStream(joinCtx, peer.ID, JoinProtocol)
		cancel()
		if err != nil {
			// We'll try again with the next peer.
			jlog.Warn("Failed to connect to peer", slog.String("error", err.Error()))
			continue
		}
		jlog.Debug("Connected to peer")
		defer stream.Close()
		// Send a join request to the peer over the stream.
		jlog.Debug("Sending join request to peer")
		_, err = stream.Write(joinData)
		if err != nil {
			return nil, fmt.Errorf("write join request: %w", err)
		}
		var b [8192]byte
		n, err := stream.Read(b[:])
		if err != nil {
			return nil, fmt.Errorf("read join response: %w", err)
		}
		if bytes.HasPrefix(b[:n], []byte("ERROR: ")) {
			return nil, fmt.Errorf("join error: %s", string(bytes.TrimPrefix(b[:n], []byte("ERROR: "))))
		}
		var resp v1.JoinResponse
		err = proto.Unmarshal(b[:n], &resp)
		if err != nil {
			return nil, fmt.Errorf("unmarshal join response: %w", err)
		}
		return &resp, nil
	}
	return nil, errors.New("no peers found to join")
}
