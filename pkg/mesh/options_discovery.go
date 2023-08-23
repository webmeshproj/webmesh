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
	"errors"
	"flag"
	"strings"

	"github.com/webmeshproj/webmesh/pkg/util/envutil"
)

const (
	DiscoveryAnnounceEnvVar            = "DISCOVERY_ANNOUNCE"
	DiscoveryPSKEnvVar                 = "DISCOVERY_PSK"
	DiscoveryUseKadDHTEnvVar           = "DISCOVERY_USE_KAD_DHT"
	DiscoveryKadBootstrapServersEnvVar = "DISCOVERY_KAD_BOOTSTRAP_SERVERS"
)

// DiscoveryOptions are options for discovering peers.
type DiscoveryOptions struct {
	// Announce is a flag to announce this peer to the discovery service.
	// Otherwise this peer will only discover other peers.
	Announce bool `json:"announce,omitempty" yaml:"announce,omitempty" toml:"announce,omitempty" mapstructure:"announce,omitempty"`
	// PSK is the pre-shared key to use as a rendezvous point for peer discovery.
	PSK string `json:"psk,omitempty" yaml:"psk,omitempty" toml:"psk,omitempty" mapstructure:"psk,omitempty"`
	// UseKadDHT is a flag to use the libp2p kademlia DHT for discovery.
	UseKadDHT bool `json:"use-kad-dht,omitempty" yaml:"use-kad-dht,omitempty" toml:"use-kad-dht,omitempty" mapstructure:"use-kad-dht,omitempty"`
	// KadBootstrapServers is a list of bootstrap servers to use for the DHT.
	// If empty or nil, the default bootstrap servers will be used.
	KadBootstrapServers []string `json:"kad-bootstrap-servers,omitempty" yaml:"kad-bootstrap-servers,omitempty" toml:"kad-bootstrap-servers,omitempty" mapstructure:"kad-bootstrap-servers,omitempty"`
}

// NewDiscoveryOptions returns a new DiscoveryOptions.
func NewDiscoveryOptions() *DiscoveryOptions {
	return &DiscoveryOptions{
		KadBootstrapServers: func() []string {
			if v := envutil.GetEnvDefault(DiscoveryKadBootstrapServersEnvVar, ""); v != "" {
				return strings.Split(v, ",")
			}
			return nil
		}(),
	}
}

// BindFlags binds the DiscoveryOptions to the flag set.
func (o *DiscoveryOptions) BindFlags(fl *flag.FlagSet, prefix ...string) {
	var p string
	if len(prefix) > 0 {
		p = strings.Join(prefix, ".") + "."
	}
	fl.BoolVar(&o.Announce, p+"discovery.announce", envutil.GetEnvDefault(DiscoveryAnnounceEnvVar, "false") == "true",
		"Announce this peer to the discovery service.")
	fl.StringVar(&o.PSK, p+"discovery.psk", envutil.GetEnvDefault(DiscoveryPSKEnvVar, ""),
		"Pre-shared key to use as a rendezvous point for peer discovery.")
	fl.BoolVar(&o.UseKadDHT, p+"discovery.use-kad-dht", envutil.GetEnvDefault(DiscoveryUseKadDHTEnvVar, "false") == "true",
		"Use the libp2p kademlia DHT for discovery.")
	fl.Func(p+"discovery.kad-bootstrap-servers", "Comma separated list of bootstrap servers to use for the DHT.", func(s string) error {
		o.KadBootstrapServers = append(o.KadBootstrapServers, strings.Split(s, ",")...)
		return nil
	})
}

// DeepCopy returns a deep copy of the DiscoveryOptions.
func (o *DiscoveryOptions) DeepCopy() *DiscoveryOptions {
	if o == nil {
		return nil
	}
	return &DiscoveryOptions{
		Announce:            o.Announce,
		PSK:                 o.PSK,
		UseKadDHT:           o.UseKadDHT,
		KadBootstrapServers: append([]string(nil), o.KadBootstrapServers...),
	}
}

// Validate validates the DiscoveryOptions.
func (o *DiscoveryOptions) Validate() error {
	if !o.Announce && !o.UseKadDHT {
		return nil
	}
	if o.PSK == "" {
		return errors.New("discovery psk must be set")
	}
	return nil
}
