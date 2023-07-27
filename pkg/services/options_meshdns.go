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
	"time"

	"github.com/webmeshproj/webmesh/pkg/util"
)

const (
	MeshDNSEnabledEnvVar        = "SERVICES_MESH_DNS_ENABLED"
	MeshDNSListenUDPEnvVar      = "SERVICES_MESH_DNS_LISTEN_UDP"
	MeshDNSListenTCPEnvVar      = "SERVICES_MESH_DNS_LISTEN_TCP"
	MeshDNSTSIGKeyEnvVar        = "SERVICES_MESH_DNS_TSIG_KEY"
	MeshDNSReusePortEnvVar      = "SERVICES_MESH_DNS_REUSE_PORT"
	MeshDNSCompressionEnvVar    = "SERVICES_MESH_DNS_COMPRESSION"
	MeshDNSRequestTimeoutEnvVar = "SERVICES_MESH_DNS_REQUEST_TIMEOUT"
)

// MeshDNSOptions are the mesh DNS options.
type MeshDNSOptions struct {
	// Enabled enables mesh DNS.
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty" toml:"enabled,omitempty"`
	// ListenUDP is the UDP address to listen on.
	ListenUDP string `yaml:"listen-udp,omitempty" json:"listen-udp,omitempty" toml:"listen-udp,omitempty"`
	// ListenTCP is the address to listen on for TCP DNS requests.
	ListenTCP string `json:"listen-tcp,omitempty" yaml:"listen-tcp,omitempty" toml:"listen-tcp,omitempty"`
	// TSIGKey is the TSIG key to use for DNS updates.
	TSIGKey string `json:"tsig-key,omitempty" yaml:"tsig-key,omitempty" toml:"tsig-key,omitempty"`
	// ReusePort sets the number of listeners to start on each port.
	// This is only supported on Linux.
	ReusePort int `json:"reuse-port,omitempty" yaml:"reuse-port,omitempty" toml:"reuse-port,omitempty"`
	// EnableCompression is true if DNS compression should be enabled.
	EnableCompression bool `json:"compression,omitempty" yaml:"compression,omitempty" toml:"compression,omitempty"`
	// RequestTimeout is the timeout for DNS requests.
	RequestTimeout time.Duration `json:"request-timeout,omitempty" yaml:"request-timeout,omitempty" toml:"request-timeout,omitempty"`
}

// NewMeshDNSOptions creates a new set of mesh DNS options.
func NewMeshDNSOptions() *MeshDNSOptions {
	return &MeshDNSOptions{
		Enabled:           false,
		ListenUDP:         ":5353",
		ListenTCP:         ":5353",
		EnableCompression: true,
		RequestTimeout:    time.Second * 5,
	}
}

// BindFlags binds the flags for the mesh DNS options.
func (o *MeshDNSOptions) BindFlags(fs *flag.FlagSet) {
	fs.BoolVar(&o.Enabled, "services.mesh-dns.enabled", util.GetEnvDefault(MeshDNSEnabledEnvVar, "false") == "true",
		"Enable mesh DNS.")
	fs.StringVar(&o.ListenUDP, "services.mesh-dns.listen-udp", util.GetEnvDefault(MeshDNSListenUDPEnvVar, ":5353"),
		"UDP address to listen on for DNS requests.")
	fs.StringVar(&o.ListenTCP, "services.mesh-dns.listen-tcp", util.GetEnvDefault(MeshDNSListenTCPEnvVar, ":5353"),
		"TCP address to listen on for DNS requests.")
	fs.StringVar(&o.TSIGKey, "services.mesh-dns.tsig-key", util.GetEnvDefault(MeshDNSTSIGKeyEnvVar, ""),
		"TSIG key to use for mesh DNS.")
	fs.IntVar(&o.ReusePort, "services.mesh-dns.reuse-port", util.GetEnvIntDefault(MeshDNSReusePortEnvVar, 0),
		"Enable SO_REUSEPORT for mesh DNS.")
	fs.BoolVar(&o.EnableCompression, "services.mesh-dns.enable-compression", util.GetEnvDefault(MeshDNSCompressionEnvVar, "true") == "true",
		"Enable DNS compression for mesh DNS.")
	fs.DurationVar(&o.RequestTimeout, "services.mesh-dns.request-timeout", util.GetEnvDurationDefault(MeshDNSRequestTimeoutEnvVar, 5*time.Second),
		"Timeout for mesh DNS requests.")
}

// Validate validates the mesh DNS options.
func (o *MeshDNSOptions) Validate() error {
	if o.Enabled {
		if o.ListenTCP == "" && o.ListenUDP == "" {
			return errors.New("must specify a TCP or UDP address for mesh DNS")
		}
	}
	return nil
}
