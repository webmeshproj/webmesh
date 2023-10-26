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
	"time"

	p2pcore "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/config"
	"github.com/multiformats/go-multiaddr"
	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport/libp2p"
)

// DiscoveryOptions are options for discovering peers.
type DiscoveryOptions struct {
	// Discover is a flag to use the libp2p kademlia DHT for discovery.
	Discover bool `koanf:"discover,omitempty"`
	// Rendezvous is the pre-shared key string to use as a rendezvous point for peer discovery.
	Rendezvous string `koanf:"rendezvous,omitempty"`
	// BootstrapServers is a list of bootstrap servers to use for the DHT.
	// If empty or nil, the default bootstrap servers will be used.
	BootstrapServers []string `koanf:"bootstrap-servers,omitempty"`
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
		Rendezvous:     psk,
		Discover:       psk != "",
		ConnectTimeout: 5 * time.Second,
	}
}

// BindFlags binds the flags for the discovery options.
func (o *DiscoveryOptions) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.StringVar(&o.Rendezvous, prefix+"rendezvous", o.Rendezvous, "pre-shared key to use as a rendezvous point for peer discovery")
	fs.BoolVar(&o.Discover, prefix+"discover", o.Discover, "use the libp2p kademlia DHT for discovery")
	fs.StringSliceVar(&o.BootstrapServers, prefix+"bootstrap-servers", o.BootstrapServers, "list of bootstrap servers to use for the DHT")
	fs.StringSliceVar(&o.LocalAddrs, prefix+"local-addrs", o.LocalAddrs, "list of local addresses to announce to the discovery service")
	fs.DurationVar(&o.ConnectTimeout, prefix+"connect-timeout", o.ConnectTimeout, "timeout for connecting to a peer")
}

// NewHostConfig returns a new HostOptions for the discovery config.
func (o *DiscoveryOptions) HostOptions(ctx context.Context, key crypto.PrivateKey) libp2p.HostOptions {
	return libp2p.HostOptions{
		Options:        []config.Option{p2pcore.Identity(key.AsIdentity())},
		BootstrapPeers: libp2p.ToMultiaddrs(o.BootstrapServers),
		LocalAddrs:     libp2p.ToMultiaddrs(o.LocalAddrs),
		ConnectTimeout: o.ConnectTimeout,
	}
}

// Validate validates the discovery options.
func (o *DiscoveryOptions) Validate() error {
	if o == nil {
		return nil
	}
	if !o.Discover {
		return nil
	}
	if o.Rendezvous == "" {
		return fmt.Errorf("rendezvous must be set when using the kademlia DHT")
	}
	if o.ConnectTimeout <= 0 {
		return fmt.Errorf("connect timeout must be greater than zero")
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
