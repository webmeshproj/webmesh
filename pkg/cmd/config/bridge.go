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
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/services/meshdns"
)

// BridgeOptions are options for the bridge.
type BridgeOptions struct {
	// Meshes are the meshes to bridge.
	Meshes map[string]*Config `koanf:"meshes,omitempty"`
	// MeshDNS are options for running a meshdns server bridging all meshes.
	MeshDNS BridgeMeshDNSOptions `koanf:"meshdns,omitempty"`
	// UseMeshDNS is true if the bridge should use the meshdns server for local name resolution.
	UseMeshDNS bool `koanf:"use-meshdns,omitempty"`
}

type BridgeMeshDNSOptions struct {
	// Enabled enables mesh DNS.
	Enabled bool `koanf:"enabled,omitempty"`
	// ListenUDP is the UDP address to listen on.
	ListenUDP string `koanf:"listen-udp,omitempty"`
	// ListenTCP is the address to listen on for TCP DNS requests.
	ListenTCP string `koanf:"listen-tcp,omitempty"`
	// ReusePort sets the number of listeners to start on each port.
	// This is only supported on Linux.
	ReusePort int `koanf:"reuse-port,omitempty"`
	// EnableCompression is true if DNS compression should be enabled.
	EnableCompression bool `koanf:"compression,omitempty"`
	// RequestTimeout is the timeout for DNS requests.
	RequestTimeout time.Duration `koanf:"request-timeout,omitempty"`
	// Forwarders are the DNS forwarders to use. If empty, the system DNS servers will be used.
	Forwarders []string `koanf:"forwarders,omitempty"`
	// SubscribeForwarders will subscribe to new nodes that are able to forward requests for other meshes.
	// These forwarders will be placed at the bottom of the forwarders list.
	SubscribeForwarders bool `koanf:"subscribe-forwarders,omitempty"`
	// DisableForwarding disables forwarding requests entirely.
	DisableForwarding bool `koanf:"disable-forwarding,omitempty"`
	// CacheSize is the size of the remote DNS cache.
	CacheSize int `koanf:"cache-size,omitempty"`
}

// BindFlags binds the flags.
func (b *BridgeOptions) BindFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&b.UseMeshDNS, "bridge.use-meshdns", false, "Use the meshdns server for local name resolution.")
	b.MeshDNS.BindFlags(fs)
	b.Meshes = map[string]*Config{}
	// Determine any bridge IDs on the command line.
	seen := map[string]struct{}{}
	if len(os.Args[1:]) > 0 {
		prefix := "--bridge."
		for _, arg := range os.Args[1:] {
			if strings.HasPrefix(arg, prefix) {
				arg = strings.TrimPrefix(arg, prefix)
				split := strings.Split(arg, ".")
				if len(split) < 2 {
					continue
				}
				meshName := split[0]
				// Make sure it won't overlap with root bridge flags
				if meshName == "meshdns" || meshName == "use-meshdns" {
					continue
				}
				seen[meshName] = struct{}{}
			}
		}
	}
	if len(seen) == 0 {
		return
	}
	for meshName := range seen {
		conf := &Config{}
		flagPrefix := "bridge." + meshName + "."
		conf.BindFlags(flagPrefix, fs)
		b.Meshes[meshName] = conf
	}
}

// BindFlags binds the flags.
func (m *BridgeMeshDNSOptions) BindFlags(fl *pflag.FlagSet) {
	fl.BoolVar(&m.Enabled, "bridge.meshdns.enabled", false, "Enable mesh DNS.")
	fl.StringVar(&m.ListenUDP, "bridge.meshdns.listen-udp", meshdns.DefaultListenUDP, "UDP address to listen on for DNS requests.")
	fl.StringVar(&m.ListenTCP, "bridge.meshdns.listen-tcp", meshdns.DefaultListenTCP, "TCP address to listen on for DNS requests.")
	fl.IntVar(&m.ReusePort, "bridge.meshdns.reuse-port", 0, "Enable SO_REUSEPORT for mesh DNS. Only available on Linux systems.")
	fl.BoolVar(&m.EnableCompression, "bridge.meshdns.compression", true, "Enable DNS compression.")
	fl.DurationVar(&m.RequestTimeout, "bridge.meshdns.request-timeout", time.Second*5, "DNS request timeout.")
	fl.StringSliceVar(&m.Forwarders, "bridge.meshdns.forwarders", nil, "DNS forwarders (default = bridged resolvers).")
	fl.BoolVar(&m.SubscribeForwarders, "bridge.meshdns.subscribe-forwarders", true, "Subscribe to new nodes that can forward requests.")
	fl.BoolVar(&m.DisableForwarding, "bridge.meshdns.disable-forwarding", false, "Disable forwarding requests.")
	fl.IntVar(&m.CacheSize, "bridge.meshdns.cache-size", 0, "Size of the remote DNS cache (0 = disabled).")
}
