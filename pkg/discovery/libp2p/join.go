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
	"net"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"

	"github.com/webmeshproj/webmesh/pkg/context"
	meshdiscovery "github.com/webmeshproj/webmesh/pkg/discovery"
	"github.com/webmeshproj/webmesh/pkg/net/system/buffers"
)

// NewKadDHTJoiner creates a new joiner for the libp2p kademlia DHT.
func NewKadDHTJoiner(ctx context.Context, opts *KadDHTOptions) (meshdiscovery.Discovery, error) {
	log := context.LoggerFrom(ctx)
	err := buffers.SetMaximumReadBuffer(2500000)
	if err != nil {
		log.Warn("Failed to set maximum read buffer", "error", err.Error())
	}
	err = buffers.SetMaximumWriteBuffer(2500000)
	if err != nil {
		log.Warn("Failed to set maximum write buffer", "error", err.Error())
	}
	host, err := libp2p.New(opts.Options...)
	if err != nil {
		return nil, fmt.Errorf("libp2p new host: %w", err)
	}
	return &kadDHTJoiner{
		opts:       opts,
		host:       host,
		triedPeers: map[string]struct{}{},
		acceptc:    make(chan io.ReadWriteCloser, 1),
		closec:     make(chan struct{}),
	}, nil
}

// kadDHTJoiner is a joiner for the libp2p kademlia DHT.
type kadDHTJoiner struct {
	opts       *KadDHTOptions
	host       host.Host
	triedPeers map[string]struct{}
	acceptc    chan io.ReadWriteCloser
	closec     chan struct{}
}

func (kad *kadDHTJoiner) Start(ctx context.Context) error {
	log := context.LoggerFrom(ctx).With("id", kad.host.ID())
	kaddht, err := dht.New(ctx, kad.host)
	if err != nil {
		return fmt.Errorf("libp2p new dht: %w", err)
	}
	err = bootstrapDHT(ctx, kad.host, kaddht, kad.opts.BootstrapPeers)
	if err != nil {
		return fmt.Errorf("libp2p bootstrap dht: %w", err)
	}
	log.Debug("Announcing join protocol with our PSK")
	routingDiscovery := drouting.NewRoutingDiscovery(kaddht)
	go kad.waitForPeers(ctx, routingDiscovery)
	return nil
}

func (kad *kadDHTJoiner) waitForPeers(ctx context.Context, routingDiscovery *drouting.RoutingDiscovery) {
	log := context.LoggerFrom(ctx).With("id", kad.host.ID())
	peerChan, err := routingDiscovery.FindPeers(ctx, kad.opts.PSK)
	if err != nil {
		log.Error("Failed to find peers, retrying in 3 seconds", "error", err.Error())
		select {
		case <-kad.closec:
			return
		case <-time.After(3 * time.Second):
			go kad.waitForPeers(ctx, routingDiscovery)
		}
	}
	for peer := range peerChan {
		if peer.ID == kad.host.ID() || len(peer.Addrs) == 0 {
			continue
		}
		if _, ok := kad.triedPeers[peer.ID.String()]; ok {
			log.Debug("Already tried peer", "peer", peer.ID)
			continue
		}
		kad.triedPeers[peer.ID.String()] = struct{}{}
		log.Debug("Found peer to join", "peer", peer.ID)
		jctx, cancel := context.WithTimeout(ctx, 5*time.Second) // TODO: Make this configurable
		s, err := kad.host.NewStream(jctx, peer.ID, JoinProtocol)
		cancel()
		if err != nil {
			log.Warn("Failed to connect to peer", "peer", peer.ID, "error", err.Error())
			continue
		}
		log.Debug("Connected to peer", "peer", peer.ID)
		kad.acceptc <- s
	}
	log.Debug("peer channel exhausted, retrying in 3 seconds")
	select {
	case <-kad.closec:
		return
	case <-time.After(3 * time.Second):
		go kad.waitForPeers(ctx, routingDiscovery)
	}
}

// Stop stops the discovery service.
func (kad *kadDHTJoiner) Stop() error {
	defer close(kad.closec)
	return kad.host.Close()
}

// Accept returns a connection to a peer.
func (kad *kadDHTJoiner) Accept() (io.ReadWriteCloser, error) {
	select {
	case <-kad.closec:
		return nil, net.ErrClosed
	case conn := <-kad.acceptc:
		return conn, nil
	}
}
