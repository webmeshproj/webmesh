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

package wireguard

import (
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"gitlab.com/webmesh/node/pkg/util"
)

const (
	WireguardListenPortEnvVar          = "WIREGUARD_LISTEN_PORT"
	WireguardNameEnvVar                = "WIREGUARD_NAME"
	WireguardForceNameEnvVar           = "WIREGUARD_FORCE_NAME"
	WireguardForceTUNEnvVar            = "WIREGUARD_FORCE_TUN"
	WireguardModprobeEnvVar            = "WIREGUARD_MODPROBE"
	WireguardMasqueradeEnvVar          = "WIREGUARD_MASQUERADE"
	WireguardAllowedIPsEnvVar          = "WIREGUARD_ALLOWED_IPS"
	WireguardPersistentKeepaliveEnvVar = "WIREGUARD_PERSISTENT_KEEPALIVE"
	WireguardEndpointOverridesEnvVar   = "WIREGUARD_ENDPOINT_OVERRIDES"
)

// Options are options for configuring the wireguard interface.
type Options struct {
	// ListenPort is the port to listen on.
	ListenPort int `yaml:"listen-port" json:"listen-port" toml:"listen-port"`
	// Name is the name of the interface.
	Name string `yaml:"name" json:"name" toml:"name"`
	// ForceName forces the use of the given name by deleting
	// any pre-existing interface with the same name.
	ForceName bool `yaml:"force-name" json:"force-name" toml:"force-name"`
	// ForceTUN forces the use of a TUN interface.
	ForceTUN bool `yaml:"force-tun" json:"force-tun" toml:"force-tun"`
	// Modprobe attempts to probe the wireguard module.
	Modprobe bool `yaml:"modprobe" json:"modprobe" toml:"modprobe"`
	// Masquerade enables masquerading of traffic from the wireguard interface.
	Masquerade bool `yaml:"masquerade" json:"masquerade" toml:"masquerade"`
	// AllowedIPs is a map of peers to allowed IPs. The peers can either be
	// public keys or regexes matching peer IDs.
	//
	// AllowedIPs in this context refers to the IP addresses that this instance
	// will route to the peer. The peer will also need to configure AllowedIPs
	// for this instance's IP address.
	//
	// The format is a whitespace separated list of key-value pairs, where the key is
	// the peer to match and the value is a comman-separated list of IP CIDRs.
	// For example:
	//
	//   "peer1=10.0.0.0/24,10.0.1.0/24 peer2="10.0.2.0/24"
	//
	AllowedIPs string `yaml:"allowed-ips" json:"allowed-ips" toml:"allowed-ips"`
	// PersistentKeepAlive is the interval at which to send keepalive packets
	// to peers. If unset, keepalive packets will automatically be sent to publicly
	// accessible peers when this instance is behind a NAT. Otherwise, no keep-alive
	// packets are sent.
	PersistentKeepAlive time.Duration `yaml:"persistent-keepalive" json:"persistent-keepalive" toml:"persistent-keepalive"`
	// EndpointOverrides is a map of peer IDs to endpoint overrides.
	EndpointOverrides string `yaml:"endpoint-overrides" json:"endpoint-overrides" toml:"endpoint-overrides"`

	// Below fields are set by the store when joining a cluster.

	// NetworkV4 is the private IPv4 network of this interface.
	// Leave empty to disable IPv4.
	NetworkV4 netip.Prefix `yaml:"-" json:"-" toml:"-"`
	// NetworkV6 is the private IPv6 network of this interface.
	// Leave empty to disable IPv6.
	NetworkV6 netip.Prefix `yaml:"-" json:"-" toml:"-"`
	// IsPublic is true if this interface is public.
	IsPublic bool `yaml:"-" json:"-" toml:"-"`
}

// NewOptions returns a new Options with sensible defaults.
func NewOptions() *Options {
	return &Options{
		ListenPort: 51820,
		Name:       "wg0",
	}
}

// BindFlags binds the options to the given flag set.
func (o *Options) BindFlags(fl *flag.FlagSet) {
	fl.IntVar(&o.ListenPort, "wireguard.listen-port", util.GetEnvIntDefault(WireguardListenPortEnvVar, 51820),
		"The WireGuard listen port.")
	fl.StringVar(&o.Name, "wireguard.name", util.GetEnvDefault(WireguardNameEnvVar, "wg0"),
		"The WireGuard interface name.")
	fl.BoolVar(&o.ForceName, "wireguard.force-name", util.GetEnvDefault(WireguardForceNameEnvVar, "false") == "true",
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

	fl.StringVar(&o.AllowedIPs, "wireguard.allowed-ips", util.GetEnvDefault(WireguardAllowedIPsEnvVar, ""),
		`AllowedIPs is a map of peers to allowed IPs. The peers can either be
peer IDs or regexes matching peer IDs. These IP addresses should not overlap 
with the private network of the WireGuard interface. AllowedIPs in this context 
refers to the IP addresses that this instance will route to the peer. The peer 
will also need to configure AllowedIPs for this instance's IP address.

The format is a whitespace separated list of key-value pairs, where the key is
the peer to match and the value is a comman-separated list of IP CIDRs.
For example:

	# Peer names
	--wireguard.allowed-ips="peer1=10.0.0.0/24,10.0.1.0/24 peer2="10.0.2.0/24"
	# Peer regexes
	--wireguard.allowed-ips="peer.*=10.0.0.0/16"
`)

	fl.StringVar(&o.EndpointOverrides, "wireguard.endpoint-overrides", util.GetEnvDefault(WireguardEndpointOverridesEnvVar, ""),
		`EndpointOverrides is a map of peer IDs to endpoint overrides.
The format is similar to allowed-ips, but the value is a single endpoint.`)
}

// Validate validates the options.
func (o *Options) Validate() error {
	if o.ListenPort <= 1024 {
		return errors.New("wireguard.listen-port must be greater than 1024")
	}
	if o.Name == "" {
		return errors.New("wireguard.name must not be empty")
	}
	if o.PersistentKeepAlive < 0 {
		return errors.New("wireguard.persistent-keepalive must not be negative")
	}
	if o.AllowedIPs != "" {
		_, err := parseAllowedIPsMap(o.AllowedIPs)
		if err != nil {
			return err
		}
	}
	if o.EndpointOverrides != "" {
		_, err := parseEndpointOverrides(o.EndpointOverrides)
		if err != nil {
			return err
		}
	}
	return nil
}

func parseAllowedIPsMap(allowedIPs string) (*peerConfigs, error) {
	spl := strings.Fields(allowedIPs)
	peerMatchers := make([]*peerMatcher, len(spl))
	for i, s := range spl {
		matcherStr, ips, found := strings.Cut(s, "=")
		if !found {
			return nil, fmt.Errorf("invalid allowed-ips format: %s", s)
		}
		var matcher peerMatcher
		peerNameRegex, err := regexp.Compile(matcherStr)
		if err == nil {
			matcher.peerNameRegex = peerNameRegex
		} else {
			matcher.peerName = matcherStr
		}
		for _, ipStr := range strings.Split(ips, ",") {
			prefix, err := netip.ParsePrefix(ipStr)
			if err != nil {
				return nil, fmt.Errorf("invalid allowed-ips format: %s", s)
			}
			matcher.allowedIPs = append(matcher.allowedIPs, prefix)
		}
		peerMatchers[i] = &matcher
	}
	return &peerConfigs{
		peerMatchers: peerMatchers,
	}, nil
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
			return nil, fmt.Errorf("invalid endpoint-overrides format: %s", s)
		}
		m[peerName] = endpointAddr
	}
	return m, nil
}

type peerConfigs struct {
	peerMatchers []*peerMatcher
}

func (o *peerConfigs) AllowedIPs(peerName string) []netip.Prefix {
	for _, matcher := range o.peerMatchers {
		if matcher.Match(peerName) {
			return matcher.allowedIPs
		}
	}
	return nil
}

type peerMatcher struct {
	peerName      string
	peerNameRegex *regexp.Regexp
	allowedIPs    []netip.Prefix
}

func (p *peerMatcher) Match(name string) bool {
	if p.peerNameRegex != nil {
		return p.peerNameRegex.MatchString(name)
	}
	return p.peerName == name
}
