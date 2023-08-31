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

	"github.com/multiformats/go-multiaddr"
	"github.com/spf13/pflag"
)

// DiscoveryOptions are options for discovering peers.
type DiscoveryOptions struct {
	// Announce is a flag to announce this peer to the discovery service.
	// Otherwise this peer will only discover other peers.
	Announce bool `koanf:"announce,omitempty"`
	// PSK is the pre-shared key to use as a rendezvous point for peer discovery.
	PSK string `koanf:"psk,omitempty"`
	// UseKadDHT is a flag to use the libp2p kademlia DHT for discovery.
	UseKadDHT bool `koanf:"use-kad-dht,omitempty"`
	// KadBootstrapServers is a list of bootstrap servers to use for the DHT.
	// If empty or nil, the default bootstrap servers will be used.
	KadBootstrapServers []string `koanf:"kad-bootstrap-servers,omitempty"`
	// AnnounceTTL is the TTL for the announcement.
	AnnounceTTL time.Duration `koanf:"announce-ttl,omitempty"`
}

// NewDiscoveryOptions returns a new DiscoveryOptions for the given PSK.
// Or one ready with sensible defaults if the PSK is empty.
func NewDiscoveryOptions(psk string, announce bool) DiscoveryOptions {
	return DiscoveryOptions{
		Announce:    announce,
		PSK:         psk,
		UseKadDHT:   psk != "",
		AnnounceTTL: time.Minute,
	}
}

// BindFlags binds the flags for the discovery options.
func (o *DiscoveryOptions) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.BoolVar(&o.Announce, prefix+"discovery.announce", false, "announce this peer to the discovery service")
	fs.StringVar(&o.PSK, prefix+"discovery.psk", "", "pre-shared key to use as a rendezvous point for peer discovery")
	fs.BoolVar(&o.UseKadDHT, prefix+"discovery.use-kad-dht", false, "use the libp2p kademlia DHT for discovery")
	fs.StringSliceVar(&o.KadBootstrapServers, prefix+"discovery.kad-bootstrap-servers", nil, "list of bootstrap servers to use for the DHT")
	fs.DurationVar(&o.AnnounceTTL, prefix+"discovery.announce-ttl", time.Minute, "TTL for the announcement")
}

// Validate validates the discovery options.
func (o *DiscoveryOptions) Validate() error {
	if len(o.KadBootstrapServers) > 0 {
		// Make sure all the addresses are valid
		for _, addr := range o.KadBootstrapServers {
			_, err := multiaddr.NewMultiaddr(addr)
			if err != nil {
				return fmt.Errorf("invalid bootstrap server address: %w", err)
			}
		}
	}
	return nil
}
