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

package campfire

import (
	"fmt"
	"sync"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// Protocol is the campfire protocol.
const Protocol = protocol.ID("/webmesh/campfire/1.0.0")

// WaitingRoom is an interface for a waiting for others to join
// the campfire.
type WaitingRoom interface {
	// Connetions returns a channel that receives new incoming connections.
	Connections() <-chan network.Stream
	// Peers returns a channel that receives new peers that have joined the
	// campfire.
	Peers() <-chan peer.AddrInfo
	// Location returns the location of the campfire.
	Location() *Location
	// Close closes the waiting room.
	Close() error
}

// waitingRoom is a simple implementation of WaitingRoom. It uses
// kad-dht to find peers.
type waitingRoom struct {
	loc    *Location
	host   host.Host
	dht    *dht.IpfsDHT
	connc  chan network.Stream
	peerc  chan peer.AddrInfo
	errc   chan error
	closec chan struct{}
}

// NewKadWaitingRoom creates a new waiting room using kad-dht to find peers.
func NewKadWaitingRoom(ctx context.Context, opts *Options) (WaitingRoom, error) {
	log := context.LoggerFrom(ctx).With("protocol", "campfire", "component", "waiting-room")
	loc, err := Find(opts.PSK, opts.TURNServers)
	if err != nil {
		return nil, fmt.Errorf("failed to find campfire: %w", err)
	}
	log.Debug("found campfire", "location", loc)
	var room waitingRoom
	room.loc = loc
	room.connc = make(chan network.Stream, 1)
	room.peerc = make(chan peer.AddrInfo, 1)
	room.errc = make(chan error, 1)
	room.closec = make(chan struct{})
	room.host, err = libp2p.New(libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"))
	if err != nil {
		return nil, fmt.Errorf("failed to create host: %w", err)
	}
	room.host.SetStreamHandler(Protocol, func(s network.Stream) {
		room.connc <- s
	})
	log.Debug("started libp2p host", "id", room.host.ID())
	room.dht, err = dht.New(ctx, room.host)
	if err != nil {
		return nil, fmt.Errorf("failed to create dht: %w", err)
	}
	log.Debug("bootstrapping the DHT")
	if err := room.dht.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("failed to bootstrap dht: %w", err)
	}
	var wg sync.WaitGroup
	for _, peerAddr := range dht.DefaultBootstrapPeers {
		peerinfo, _ := peer.AddrInfoFromP2pAddr(peerAddr)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := room.host.Connect(ctx, *peerinfo); err != nil {
				log.Warn("Error connectiong to host", "error", err.Error())
			} else {
				log.Debug("Connection established with bootstrap node", "peer", *peerinfo)
			}
		}()
	}
	wg.Wait()
	routingDiscovery := routing.NewRoutingDiscovery(room.dht)
	dutil.Advertise(ctx, routingDiscovery, room.loc.Secret)
	log.Debug("DHT bootstrapped, waiting by the camp fire...")
	go func() {
		for {
			peerinfo, err := routingDiscovery.FindPeers(ctx, room.loc.Secret)
			if err != nil {
				log.Error("failed to find peers", "error", err.Error())
				room.errc <- err
				return
			}
			select {
			case <-room.closec:
				return
			case peer := <-peerinfo:
				log.Debug("found another peer at the campfire", "peer", peer)
				room.peerc <- peer
			}
		}
	}()
	return &room, nil
}

// Connections returns a channel that receives new incoming connections.
func (w *waitingRoom) Connections() <-chan network.Stream {
	return w.connc
}

// Peers returns a channel that receives new peers that have joined the
// campfire.
func (w *waitingRoom) Peers() <-chan peer.AddrInfo {
	return w.peerc
}

// Location returns the location of the campfire.
func (w *waitingRoom) Location() *Location {
	return w.loc
}

// Close closes the waiting room.
func (w *waitingRoom) Close() error {
	close(w.closec)
	defer w.dht.Close()
	return w.host.Close()
}
