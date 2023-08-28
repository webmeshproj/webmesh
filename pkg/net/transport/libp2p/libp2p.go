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

// Package libp2p provides discovery mechanisms using Kademlia DHT.
package libp2p

import (
	"fmt"
	"sync"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// JoinProtocol is the protocol used for joining a mesh.
const JoinProtocol = protocol.ID("/webmesh/join/0.0.1")

func bootstrapDHT(ctx context.Context, host host.Host, kaddht *dht.IpfsDHT, servers []multiaddr.Multiaddr) error {
	log := context.LoggerFrom(ctx)
	err := kaddht.Bootstrap(ctx)
	if err != nil {
		return fmt.Errorf("libp2p dht bootstrap: %w", err)
	}
	if len(servers) == 0 {
		servers = dht.DefaultBootstrapPeers
	}
	var wg sync.WaitGroup
	for _, peerAddr := range servers {
		peerinfo, err := peer.AddrInfoFromP2pAddr(peerAddr)
		if err != nil {
			log.Warn("Failed to parse bootstrap peer address", "error", err.Error())
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := host.Connect(ctx, *peerinfo); err != nil {
				log.Warn("Failed to connect to bootstrap peer", "error", err.Error())
				return
			}
			log.Debug("Connection established with bootstrap node", "node", peerinfo.String())
		}()
	}
	wg.Wait()
	return nil
}
