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
	"sync"
	"sync/atomic"
	"time"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// NewDHT returns a DHT for given host. If bootstrap peers is empty, the default
// bootstrap peers will be used.
func NewDHT(ctx context.Context, host host.Host, bootstrapPeers []multiaddr.Multiaddr, connectTimeout time.Duration) (*dht.IpfsDHT, error) {
	if len(bootstrapPeers) == 0 {
		bootstrapPeers = dht.DefaultBootstrapPeers
	}
	kaddht, err := newDHT(ctx, host, bootstrapPeers, connectTimeout)
	return kaddht, err
}

func newDHT(ctx context.Context, host host.Host, bootstrapPeers []multiaddr.Multiaddr, connectTimeout time.Duration) (*dht.IpfsDHT, error) {
	kaddht, err := dht.New(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("libp2p new dht: %w", err)
	}
	err = bootstrapDHT(ctx, host, kaddht, bootstrapPeers, connectTimeout)
	if err != nil {
		defer kaddht.Close()
		return nil, fmt.Errorf("libp2p bootstrap dht: %w", err)
	}
	return kaddht, nil
}

func bootstrapDHT(ctx context.Context, host host.Host, kaddht *dht.IpfsDHT, servers []multiaddr.Multiaddr, connectTimeout time.Duration) error {
	log := context.LoggerFrom(ctx)
	err := kaddht.Bootstrap(ctx)
	if err != nil {
		return fmt.Errorf("libp2p dht bootstrap: %w", err)
	}
	var wg sync.WaitGroup
	var errs atomic.Int32
	for _, peerAddr := range servers {
		peerinfo, err := peer.AddrInfoFromP2pAddr(peerAddr)
		if err != nil {
			log.Debug("Failed to parse bootstrap peer address", "error", err.Error())
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			var connectCtx context.Context
			var cancel context.CancelFunc
			if connectTimeout > 0 {
				connectCtx, cancel = context.WithTimeout(ctx, connectTimeout)
			} else {
				connectCtx, cancel = context.WithCancel(ctx)
			}
			defer cancel()
			if err := host.Connect(connectCtx, *peerinfo); err != nil {
				log.Warn("Failed to connect to DHT bootstrap peer", "error", err.Error())
				errs.Add(1)
				return
			}
			log.Debug("Connection established with bootstrap node", "node", peerinfo.String())
		}()
	}
	wg.Wait()
	if len(servers) == int(errs.Load()) {
		return fmt.Errorf("libp2p dht bootstrap: failed to connect to any bootstrap peer")
	}
	return nil
}
