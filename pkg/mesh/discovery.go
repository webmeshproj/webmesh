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

package mesh

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/multiformats/go-multiaddr"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/net/transport/libp2p"
)

// DiscoveryOptions are options for performing peer discovery.
type DiscoveryOptions struct {
	// BootstrapServers are bootstrap servers for the DHT.
	BootstrapServers []string
	// PSK is the pre-shared key to use as a rendezvous point for peer discovery.
	PSK string
	// DiscoveryTTL is the time-to-live for the discovery service.
	DiscoveryTTL time.Duration
	// Announce is a flag to announce this peer to the discovery service.
	Announce bool
	// LocalAddrs are the local addresses to announce to the discovery service.
	// If empty, the default local addresses will be used.
	LocalAddrs []multiaddr.Multiaddr
}

func (s *meshStore) AnnounceDHT(ctx context.Context, opts DiscoveryOptions) error {
	log := context.LoggerFrom(ctx)
	log.Info("Announcing peer discovery service")
	var peers []multiaddr.Multiaddr
	for _, p := range opts.BootstrapServers {
		mul, err := multiaddr.NewMultiaddr(p)
		if err != nil {
			return fmt.Errorf("new multiaddr: %w", err)
		}
		peers = append(peers, mul)
	}
	announceOpts := libp2p.DHTAnnounceOptions{
		PSK:            opts.PSK,
		BootstrapPeers: peers,
		DiscoveryTTL:   opts.DiscoveryTTL,
	}
	discover, err := libp2p.NewDHTAnnouncer(ctx, announceOpts, transport.JoinServerFunc(s.proxyJoinToLeader))
	if err != nil {
		return fmt.Errorf("new kad dht announcer: %w", err)
	}
	s.discovermu.Lock()
	s.discoveries[opts.PSK] = discover
	s.discovermu.Unlock()
	return nil
}

func (s *meshStore) LeaveDHT(ctx context.Context, psk string) error {
	s.discovermu.Lock()
	defer s.discovermu.Unlock()
	if d, ok := s.discoveries[psk]; ok {
		if err := d.Close(); err != nil {
			return err
		}
		delete(s.discoveries, psk)
	}
	return nil
}

func (s *meshStore) proxyJoinToLeader(ctx context.Context, req *v1.JoinRequest) (*v1.JoinResponse, error) {
	log := context.LoggerFrom(ctx)
	c, err := s.DialLeader(ctx)
	if err != nil {
		log.Error("failed to dial leader", slog.String("error", err.Error()))
		return nil, err
	}
	defer c.Close()
	resp, err := v1.NewMembershipClient(c).Join(ctx, req)
	if err != nil {
		log.Error("failed to proxy join to cluster", slog.String("error", err.Error()))
		return nil, err
	}
	return resp, nil
}
