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
	"flag"
	"net/netip"

	"gitlab.com/webmesh/node/pkg/util"
)

const (
	WireguardListenPortEnvVar = "WIREGUARD_LISTEN_PORT"
	WireguardEndpointEnvVar   = "WIREGUARD_ENDPOINT"
	WireguardNameEnvVar       = "WIREGUARD_NAME"
	WireguardForceNameEnvVar  = "WIREGUARD_FORCE_NAME"
	WireguardForceTUNEnvVar   = "WIREGUARD_FORCE_TUN"
	WireguardNoModprobeEnvVar = "WIREGUARD_NO_MODPROBE"
	WireguardMasqueradeEnvVar = "WIREGUARD_MASQUERADE"
)

// Options are options for configuring the wireguard interface.
type Options struct {
	// ListenPort is the port to listen on.
	ListenPort int
	// Endpoint is the endpoint to use for the wireguard interface.
	Endpoint string
	// Name is the name of the interface.
	Name string
	// ForceName forces the use of the given name by deleting
	// any pre-existing interface with the same name.
	ForceName bool
	// NetworkV4 is the private IPv4 network of this interface.
	// Leave empty to disable IPv4.
	NetworkV4 netip.Prefix
	// NetworkV6 is the private IPv6 network of this interface.
	// Leave empty to disable IPv6.
	NetworkV6 netip.Prefix
	// ForceTUN forces the use of a TUN interface.
	ForceTUN bool
	// NoModprobe disables modprobe.
	NoModprobe bool
	// Masquerade enables masquerading of traffic from the wireguard interface.
	Masquerade bool
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
		"The wireguard listen port.")
	fl.StringVar(&o.Endpoint, "wireguard.endpoint", util.GetEnvDefault(WireguardEndpointEnvVar, ""),
		"The wireguard endpoint. If unset, inbound tunnels will not be accepted.")
	fl.StringVar(&o.Name, "wireguard.name", util.GetEnvDefault(WireguardNameEnvVar, "wg0"),
		"The wireguard interface name.")
	fl.BoolVar(&o.ForceName, "wireguard.force-name", util.GetEnvDefault(WireguardForceNameEnvVar, "false") == "true",
		"Force the use of the given name by deleting any pre-existing interface with the same name.")
	fl.BoolVar(&o.ForceTUN, "wireguard.force-tun", util.GetEnvDefault(WireguardForceTUNEnvVar, "false") == "true",
		"Force the use of a TUN interface.")
	fl.BoolVar(&o.NoModprobe, "wireguard.no-modprobe", util.GetEnvDefault(WireguardNoModprobeEnvVar, "false") == "true",
		"Don't attempt to probe the wireguard module.")
	fl.BoolVar(&o.Masquerade, "wireguard.masquerade", util.GetEnvDefault(WireguardMasqueradeEnvVar, "false") == "true",
		"Masquerade traffic from the wireguard interface.")
}
