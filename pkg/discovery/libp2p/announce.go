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

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"

	"github.com/webmeshproj/webmesh/pkg/context"
	meshdiscovery "github.com/webmeshproj/webmesh/pkg/discovery"
	"github.com/webmeshproj/webmesh/pkg/net/system/buffers"
)

// NewKadDHTAnnouncer creates a new announcer for the libp2p kademlia DHT.
func NewKadDHTAnnouncer(ctx context.Context, opts *KadDHTOptions) (meshdiscovery.Discovery, error) {
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
	return &kadDHTAnnouncer{
		opts:    opts,
		host:    host,
		acceptc: make(chan io.ReadWriteCloser, 1),
		closec:  make(chan struct{}),
		stop:    func() {},
	}, nil
}

// kadDHTAnnouncer is an announcer for the libp2p kademlia DHT.
type kadDHTAnnouncer struct {
	opts    *KadDHTOptions
	host    host.Host
	acceptc chan io.ReadWriteCloser
	closec  chan struct{}
	stop    func()
}

// Start starts the discovery service.
func (kad *kadDHTAnnouncer) Start(ctx context.Context) error {
	log := context.LoggerFrom(ctx).With("id", kad.host.ID())
	kad.host.SetStreamHandler(JoinProtocol, func(s network.Stream) {
		log.Debug("Handling join protocol stream", "peer", s.Conn().RemotePeer())
		kad.acceptc <- s
	})
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
	announceCtx, cancel := context.WithCancel(context.Background())
	kad.stop = cancel
	var opts []discovery.Option
	if kad.opts.DiscoveryTTL > 0 {
		opts = append(opts, discovery.TTL(kad.opts.DiscoveryTTL))
	}
	dutil.Advertise(announceCtx, routingDiscovery, kad.opts.PSK, opts...)
	return nil
}

// Stop stops the discovery service.
func (kad *kadDHTAnnouncer) Stop() error {
	defer close(kad.closec)
	kad.stop()
	return kad.host.Close()
}

// Accept returns a connection to a peer.
func (kad *kadDHTAnnouncer) Accept() (io.ReadWriteCloser, error) {
	select {
	case <-kad.closec:
		return nil, net.ErrClosed
	case conn := <-kad.acceptc:
		return conn, nil
	}
}
