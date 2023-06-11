/*
Copyright 2023.

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

package store

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/webmeshproj/node/pkg/net/system"
	"github.com/webmeshproj/node/pkg/util"
)

const (
	WireguardListenPortEnvVar          = "WIREGUARD_LISTEN_PORT"
	WireguardNameEnvVar                = "WIREGUARD_INTERFACE_NAME"
	WireguardForceNameEnvVar           = "WIREGUARD_FORCE_INTERFACE_NAME"
	WireguardForceTUNEnvVar            = "WIREGUARD_FORCE_TUN"
	WireguardModprobeEnvVar            = "WIREGUARD_MODPROBE"
	WireguardMasqueradeEnvVar          = "WIREGUARD_MASQUERADE"
	WireguardAllowedIPsEnvVar          = "WIREGUARD_ALLOWED_IPS"
	WireguardPersistentKeepaliveEnvVar = "WIREGUARD_PERSISTENT_KEEPALIVE"
	WireguardEndpointOverridesEnvVar   = "WIREGUARD_ENDPOINT_OVERRIDES"
	WireguardMTUEnvVar                 = "WIREGUARD_MTU"
)

// DefaultInterfaceName is the default name of the WireGuard interface.
const DefaultInterfaceName = "webmesh0"

// WireGuardOptions are options for configuring the WireGuard interface.
type WireGuardOptions struct {
	// ListenPort is the port to listen on.
	ListenPort int `yaml:"listen-port,omitempty" json:"listen-port,omitempty" toml:"listen-port,omitempty"`
	// InterfaceName is the name of the interface.
	InterfaceName string `yaml:"interface-name,omitempty" json:"interface-name,omitempty" toml:"interface-name,omitempty"`
	// ForceInterfaceName forces the use of the given name by deleting
	// any pre-existing interface with the same name.
	ForceInterfaceName bool `yaml:"force-interface-name,omitempty" json:"force-interface-name,omitempty" toml:"force-interface-name,omitempty"`
	// ForceTUN forces the use of a TUN interface.
	ForceTUN bool `yaml:"force-tun,omitempty" json:"force-tun,omitempty" toml:"force-tun,omitempty"`
	// Modprobe attempts to probe the wireguard module.
	Modprobe bool `yaml:"modprobe,omitempty" json:"modprobe,omitempty" toml:"modprobe,omitempty"`
	// Masquerade enables masquerading of traffic from the wireguard interface.
	Masquerade bool `yaml:"masquerade,omitempty" json:"masquerade,omitempty" toml:"masquerade,omitempty"`
	// PersistentKeepAlive is the interval at which to send keepalive packets
	// to peers. If unset, keepalive packets will automatically be sent to publicly
	// accessible peers when this instance is behind a NAT. Otherwise, no keep-alive
	// packets are sent.
	PersistentKeepAlive time.Duration `yaml:"persistent-keepalive,omitempty" json:"persistent-keepalive,omitempty" toml:"persistent-keepalive,omitempty"`
	// EndpointOverrides is a map of peer IDs to endpoint overrides.
	EndpointOverrides string `yaml:"endpoint-overrides,omitempty" json:"endpoint-overrides,omitempty" toml:"endpoint-overrides,omitempty"`
	// MTU is the MTU to use for the interface.
	MTU int `yaml:"mtu,omitempty" json:"mtu,omitempty" toml:"mtu,omitempty"`
}

// WireGuardOptions returns a new WireGuardOptions with sensible defaults.
func NewWireGuardOptions() *WireGuardOptions {
	return &WireGuardOptions{
		ListenPort:    51820,
		InterfaceName: DefaultInterfaceName,
		MTU:           system.DefaultMTU,
	}
}

// BindFlags binds the options to the given flag set.
func (o *WireGuardOptions) BindFlags(fl *flag.FlagSet) {
	fl.IntVar(&o.ListenPort, "wireguard.listen-port", util.GetEnvIntDefault(WireguardListenPortEnvVar, 51820),
		"The WireGuard listen port.")
	fl.StringVar(&o.InterfaceName, "wireguard.interface-name", util.GetEnvDefault(WireguardNameEnvVar, DefaultInterfaceName),
		"The WireGuard interface name.")
	fl.BoolVar(&o.ForceInterfaceName, "wireguard.force-interface-name", util.GetEnvDefault(WireguardForceNameEnvVar, "false") == "true",
		"Force the use of the given name by deleting any pre-existing interface with the same name.")
	fl.BoolVar(&o.ForceTUN, "wireguard.force-tun", util.GetEnvDefault(WireguardForceTUNEnvVar, "false") == "true",
		"Force the use of a TUN interface.")
	fl.BoolVar(&o.Modprobe, "wireguard.modprobe", util.GetEnvDefault(WireguardModprobeEnvVar, "false") == "true",
		"Attempt to load the WireGuard kernel module.")
	fl.BoolVar(&o.Masquerade, "wireguard.masquerade", util.GetEnvDefault(WireguardMasqueradeEnvVar, "false") == "true",
		"Masquerade traffic from the WireGuard interface.")
	fl.DurationVar(&o.PersistentKeepAlive, "wireguard.persistent-keepalive", util.GetEnvDurationDefault(WireguardPersistentKeepaliveEnvVar, 0),
		`PersistentKeepAlive is the interval at which to send keepalive packets
to peers. If unset, keepalive packets will automatically be sent to publicly
accessible peers when this instance is behind a NAT. Otherwise, no keep-alive
packets are sent.`)

	fl.StringVar(&o.EndpointOverrides, "wireguard.endpoint-overrides", util.GetEnvDefault(WireguardEndpointOverridesEnvVar, ""),
		`EndpointOverrides is a map of peer IDs to endpoint overrides.
The format is similar to allowed-ips, but the value is a single endpoint.`)

	fl.IntVar(&o.MTU, "wireguard.mtu", util.GetEnvIntDefault(WireguardMTUEnvVar, system.DefaultMTU),
		"The MTU to use for the interface.")
}

// Validate validates the options.
func (o *WireGuardOptions) Validate() error {
	if o.ListenPort <= 1024 {
		return errors.New("wireguard.listen-port must be greater than 1024")
	}
	if o.InterfaceName == "" {
		return errors.New("wireguard.name must not be empty")
	}
	if o.PersistentKeepAlive < 0 {
		return errors.New("wireguard.persistent-keepalive must not be negative")
	}
	if o.MTU < 0 {
		return errors.New("wireguard.mtu must not be negative")
	} else if o.MTU > system.MaxMTU {
		return fmt.Errorf("wireguard.mtu must not be greater than %d", system.MaxMTU)
	}
	if o.EndpointOverrides != "" {
		_, err := parseEndpointOverrides(o.EndpointOverrides)
		if err != nil {
			return err
		}
	}
	return nil
}

func parseEndpointOverrides(overrides string) (map[string]netip.AddrPort, error) {
	spl := strings.Fields(overrides)
	m := make(map[string]netip.AddrPort, len(spl))
	for _, s := range spl {
		peerName, endpoint, found := strings.Cut(s, "=")
		if !found {
			return nil, fmt.Errorf("invalid endpoint-overrides format: %s", s)
		}
		endpointAddr, err := netip.ParseAddrPort(endpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint-overrides format: %s: %w", s, err)
		}
		m[peerName] = endpointAddr
	}
	return m, nil
}