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

package discovery

import (
	"bufio"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/context"
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

// NewKadDHTAnnouncer creates a new announcer for the libp2p kademlia DHT.
func NewKadDHTAnnouncer(opts *KadDHTOptions) (Discovery, error) {
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
		rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))
		kad.acceptc <- &kadStream{ReadWriter: rw, s: s}
	})
	kaddht, err := dht.New(ctx, kad.host)
	if err != nil {
		return fmt.Errorf("libp2p new dht: %w", err)
	}
	err = kaddht.Bootstrap(ctx)
	if err != nil {
		return fmt.Errorf("libp2p dht bootstrap: %w", err)
	}
	bootstrapPeers := kad.opts.BootstrapPeers
	if len(bootstrapPeers) == 0 {
		bootstrapPeers = dht.DefaultBootstrapPeers
	}
	var wg sync.WaitGroup
	for _, peerAddr := range bootstrapPeers {
		peerinfo, err := peer.AddrInfoFromP2pAddr(peerAddr)
		if err != nil {
			log.Warn("Failed to parse bootstrap peer address", "error", err.Error())
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := kad.host.Connect(ctx, *peerinfo); err != nil {
				log.Warn("Failed to connect to bootstrap peer", "error", err.Error())
				return
			}
			log.Debug("Connection established with bootstrap node", "node", peerinfo.String())
		}()
	}
	wg.Wait()
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
		return nil, io.EOF
	case conn := <-kad.acceptc:
		return conn, nil
	}
}

type kadStream struct {
	*bufio.ReadWriter
	s network.Stream
}

func (k *kadStream) Close() error { return k.s.Close() }
