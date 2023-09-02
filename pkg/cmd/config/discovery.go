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

package config

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/multiformats/go-multiaddr"
	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport/libp2p"
)

// DiscoveryOptions are options for discovering peers.
type DiscoveryOptions struct {
	// Announce is a flag to announce this peer to the discovery service.
	// Otherwise this peer will only discover other peers.
	Announce bool `koanf:"announce,omitempty"`
	// Discover is a flag to use the libp2p kademlia DHT for discovery.
	Discover bool `koanf:"discover,omitempty"`
	// PSK is the pre-shared key to use as a rendezvous point for peer discovery.
	PSK string `koanf:"psk,omitempty"`
	// BootstrapServers is a list of bootstrap servers to use for the DHT.
	// If empty or nil, the default bootstrap servers will be used.
	BootstrapServers []string `koanf:"bootstrap-servers,omitempty"`
	// AnnounceTTL is the TTL for the announcement.
	AnnounceTTL time.Duration `koanf:"announce-ttl,omitempty"`
	// LocalAddrs is a list of local addresses to announce to the discovery service.
	// If empty, the default local addresses will be used.
	LocalAddrs []string `koanf:"local-addrs,omitempty"`
	// ConnectTimeout is the timeout for connecting to a peer.
	ConnectTimeout time.Duration `koanf:"connect-timeout,omitempty"`
}

// NewDiscoveryOptions returns a new DiscoveryOptions for the given PSK.
// Or one ready with sensible defaults if the PSK is empty.
func NewDiscoveryOptions(psk string, announce bool) DiscoveryOptions {
	return DiscoveryOptions{
		Announce:       announce,
		PSK:            psk,
		Discover:       psk != "",
		AnnounceTTL:    time.Minute,
		ConnectTimeout: 3 * time.Second,
	}
}

// BindFlags binds the flags for the discovery options.
func (o *DiscoveryOptions) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.BoolVar(&o.Announce, prefix+"discovery.announce", false, "announce this peer to the discovery service")
	fs.StringVar(&o.PSK, prefix+"discovery.psk", "", "pre-shared key to use as a rendezvous point for peer discovery")
	fs.BoolVar(&o.Discover, prefix+"discovery.discover", false, "use the libp2p kademlia DHT for discovery")
	fs.StringSliceVar(&o.BootstrapServers, prefix+"discovery.bootstrap-servers", nil, "list of bootstrap servers to use for the DHT")
	fs.DurationVar(&o.AnnounceTTL, prefix+"discovery.announce-ttl", time.Minute, "TTL for the announcement")
	fs.StringSliceVar(&o.LocalAddrs, prefix+"discovery.local-addrs", nil, "list of local addresses to announce to the discovery service")
	fs.DurationVar(&o.ConnectTimeout, prefix+"discovery.connect-timeout", 3*time.Second, "timeout for connecting to a peer")
}

// NewHostConfig returns a new HostOptions for the discovery config.
func (o *DiscoveryOptions) HostOptions(ctx context.Context) libp2p.HostOptions {
	return libp2p.HostOptions{
		BootstrapPeers: func() []multiaddr.Multiaddr {
			out := make([]multiaddr.Multiaddr, 0)
			for _, addr := range o.BootstrapServers {
				maddr, err := multiaddr.NewMultiaddr(addr)
				if err != nil {
					context.LoggerFrom(ctx).Warn("Invalid local multiaddr", slog.String("address", addr))
					continue
				}
				out = append(out, maddr)
			}
			return out
		}(),
		LocalAddrs: func() []multiaddr.Multiaddr {
			out := make([]multiaddr.Multiaddr, 0)
			for _, addr := range o.LocalAddrs {
				maddr, err := multiaddr.NewMultiaddr(addr)
				if err != nil {
					context.LoggerFrom(ctx).Warn("Invalid local multiaddr", slog.String("address", addr))
					continue
				}
				out = append(out, maddr)
			}
			return out
		}(),
		ConnectTimeout: o.ConnectTimeout,
	}
}

// Validate validates the discovery options.
func (o *DiscoveryOptions) Validate() error {
	if len(o.BootstrapServers) > 0 {
		// Make sure all the addresses are valid
		for _, addr := range o.BootstrapServers {
			_, err := multiaddr.NewMultiaddr(addr)
			if err != nil {
				return fmt.Errorf("invalid bootstrap server address: %w", err)
			}
		}
	}
	if o.Discover || o.Announce {
		if o.PSK == "" {
			return fmt.Errorf("pre-shared key must be set when using the kademlia DHT")
		}
		if o.Announce && o.AnnounceTTL <= 0 {
			return fmt.Errorf("announce TTL must be greater than zero")
		}
	}
	if len(o.LocalAddrs) > 0 {
		// Make sure all the addresses are valid
		for _, addr := range o.LocalAddrs {
			_, err := multiaddr.NewMultiaddr(addr)
			if err != nil {
				return fmt.Errorf("invalid local address: %w", err)
			}
		}
	}
	if len(o.BootstrapServers) > 0 {
		for _, addr := range o.BootstrapServers {
			_, err := multiaddr.NewMultiaddr(addr)
			if err != nil {
				return fmt.Errorf("invalid bootstrap server address: %w", err)
			}
		}
	}
	return nil
}
