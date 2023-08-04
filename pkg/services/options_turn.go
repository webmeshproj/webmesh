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

package services

import (
	"errors"
	"flag"
	"strings"

	"github.com/webmeshproj/webmesh/pkg/util"
)

const (
	TURNEnabledEnvVar             = "SERVICES_TURN_ENABLED"
	TURNServerEndpointEnvVar      = "SERVICES_TURN_ENDPOINT"
	TURNServerPublicIPEnvVar      = "SERVICES_TURN_PUBLIC_IP"
	TURNServerListenAddressEnvVar = "SERVICES_TURN_LISTEN_ADDRESS"
	TURNServerPortEnvVar          = "SERVICES_TURN_SERVER_PORT"
	TURNServerRealmEnvVar         = "SERVICES_TURN_SERVER_REALM"
	TURNSTUNPortRangeEnvVar       = "SERVICES_TURN_STUN_PORT_RANGE"
)

// TURNOptions are the TURN Server options.
type TURNOptions struct {
	// Enabled enables the TURN server.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty" toml:"enabled,omitempty"`
	// Endpoint is the endpoint to advertise for the TURN server. If empty, the public IP and listen port is used.
	Endpoint string `json:"endpoint,omitempty" yaml:"endpoint,omitempty" toml:"endpoint,omitempty"`
	// PublicIP is the address advertised for STUN requests.
	PublicIP string `json:"public-ip,omitempty" yaml:"public-ip,omitempty" toml:"public-ip,omitempty"`
	// ListenAddress is the address to listen on for TURN connections.
	ListenAddress string `json:"listen-address,omitempty" yaml:"listen-address,omitempty" toml:"listen-address,omitempty"`
	// ListenPort is the port to listen on for TURN connections.
	ListenPort int `json:"listen-port,omitempty" yaml:"listen-port,omitempty" toml:"listen-port,omitempty"`
	// ServerRealm is the realm used for TURN server authentication.
	ServerRealm string `json:"realm,omitempty" yaml:"realm,omitempty" toml:"realm,omitempty"`
	// STUNPortRange is the port range to use for STUN.
	STUNPortRange string `json:"stun-port-range,omitempty" yaml:"stun-port-range,omitempty" toml:"stun-port-range,omitempty"`
}

// NewTURNOptions creates a new TURNOptions with default values.
func NewTURNOptions() *TURNOptions {
	return &TURNOptions{
		Enabled:       false,
		ListenAddress: "0.0.0.0",
		ListenPort:    3478,
		ServerRealm:   "webmesh.io",
		STUNPortRange: "49152-65535",
	}
}

// BindFlags binds the flags.
func (o *TURNOptions) BindFlags(fs *flag.FlagSet, prefix ...string) {
	var p string
	if len(prefix) > 0 {
		p = strings.Join(prefix, ".") + "."
	}
	fs.BoolVar(&o.Enabled, p+"services.turn.enabled", util.GetEnvDefault(TURNEnabledEnvVar, "false") == "true",
		"Enable the TURN server.")
	fs.StringVar(&o.Endpoint, p+"services.turn.endpoint", util.GetEnvDefault(TURNServerEndpointEnvVar, ""),
		"The TURN server endpoint. If empty, the public IP will be used.")
	fs.StringVar(&o.PublicIP, p+"services.turn.public-ip", util.GetEnvDefault(TURNServerPublicIPEnvVar, ""),
		"The address advertised for STUN requests.")
	fs.StringVar(&o.ListenAddress, p+"services.turn.listen-address", util.GetEnvDefault(TURNServerListenAddressEnvVar, "0.0.0.0"),
		"Address to listen on for TURN connections.")
	fs.IntVar(&o.ListenPort, p+"services.turn.listen-port", util.GetEnvIntDefault(TURNServerPortEnvVar, 3478),
		"Port to listen on for TURN connections.")
	fs.StringVar(&o.ServerRealm, p+"services.turn.server-realm", util.GetEnvDefault(TURNServerRealmEnvVar, "webmesh.io"),
		"Realm used for TURN server authentication.")
	fs.StringVar(&o.STUNPortRange, p+"services.turn.stun-port-range", util.GetEnvDefault(TURNSTUNPortRangeEnvVar, "49152-65535"),
		"Port range to use for STUN.")
}

// Validate validates the options.
func (o *TURNOptions) Validate() error {
	if o.Enabled {
		if o.PublicIP == "" {
			return errors.New("must specify a public IP for the TURN server")
		}
		if o.ListenPort <= 0 {
			return errors.New("must specify a port for the TURN server")
		}
		if o.STUNPortRange == "" {
			return errors.New("must specify STUN port range")
		}
	}
	return nil
}
