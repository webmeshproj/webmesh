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

	"github.com/webmeshproj/node/pkg/util"
)

const (
	BootstrapEnabledEnvVar              = "BOOTSTRAP_ENABLED"
	AdvertiseAddressEnvVar              = "BOOTSTRAP_ADVERTISE_ADDRESS"
	BootstrapServersEnvVar              = "BOOTSTRAP_SERVERS"
	BootstrapServersGRPCPortsEnvVar     = "BOOTSTRAP_SERVERS_GRPC_PORTS"
	BootstrapIPv4NetworkEnvVar          = "BOOTSTRAP_IPV4_NETWORK"
	BootstrapAdminEnvVar                = "BOOTSTRAP_ADMIN"
	BootstrapVotersEnvVar               = "BOOTSTRAP_VOTERS"
	BootstrapDefaultNetworkPolicyEnvVar = "BOOTSTRAP_DEFAULT_NETWORK_POLICY"
	ForceBootstrapClusterEnvVar         = "BOOTSTRAP_FORCE"
)

// BootstrapOptions are the bootstrap options.
type BootstrapOptions struct {
	// Enabled is the flag to attempt bootstrapping. If true, the node will only bootstrap a new cluster
	// if no data is found. To force a bootstrap, set Force to true.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty" toml:"enabled,omitempty"`
	// AdvertiseAddress is the initial address to advertise for raft consensus.
	AdvertiseAddress string `json:"advertise-address,omitempty" yaml:"advertise-address,omitempty" toml:"advertise-address,omitempty"`
	// Servers is a comma separated list of servers to bootstrap with. If not empty, all
	// nodes in the list should be started with the same list and BootstrapIPv4Network. If the
	// BootstrapIPv4Network is not the same, the first node to become leader will pick it. Servers
	// should be in the form of <node-id>=<address> where address is the advertise address.
	Servers string `json:"servers,omitempty" yaml:"servers,omitempty" toml:"servers,omitempty"`
	// ServersGRPCPorts is a comma separated list of gRPC ports to bootstrap with. If empty, the node will
	// use the advertise address and local gRPC port for every node in BootstrapServers. Ports should be
	// in the form of <node-id>=<port>.
	ServersGRPCPorts string `json:"servers-grpc-ports,omitempty" yaml:"servers-grpc-ports,omitempty" toml:"servers-grpc-ports,omitempty"`
	// IPv4Network is the IPv4 network of the mesh to write to the database when bootstraping a new cluster.
	IPv4Network string `json:"ipv4-network,omitempty" yaml:"ipv4-network,omitempty" toml:"ipv4-network,omitempty"`
	// Admin is the user and/or node name to assign administrator privileges to when bootstraping a new cluster.
	Admin string `json:"admin,omitempty" yaml:"admin,omitempty" toml:"admin,omitempty"`
	// Voters is a comma separated list of node IDs to assign voting privileges to when bootstraping a new cluster.
	// BootstrapServers are automatically added to this list.
	Voters string `json:"voters,omitempty" yaml:"voters,omitempty" toml:"voters,omitempty"`
	// DefaultNetworkPolicy is the default network policy to apply to the mesh when bootstraping a new cluster.
	DefaultNetworkPolicy string `json:"default-network-policy,omitempty" yaml:"default-network-policy,omitempty" toml:"default-network-policy,omitempty"`
	// Force is the force new bootstrap flag.
	Force bool `json:"force,omitempty" yaml:"force,omitempty" toml:"force,omitempty"`
}

// NetworkPolicy is a type of network policy.
type NetworkPolicy string

const (
	// NetworkPolicyAccept is the accept network policy.
	NetworkPolicyAccept NetworkPolicy = "accept"
	// NetworkPolicyDeny is the deny network policy.
	NetworkPolicyDeny NetworkPolicy = "deny"
)

// IsValid returns if the network policy is valid.
func (n NetworkPolicy) IsValid() bool {
	switch n {
	case NetworkPolicyAccept, NetworkPolicyDeny:
		return true
	default:
		return false
	}
}

// NewBootstrapOptions creates a new BootstrapOptions.
func NewBootstrapOptions() *BootstrapOptions {
	return &BootstrapOptions{
		Enabled:              false,
		IPv4Network:          "172.16.0.0/12",
		Admin:                "admin",
		DefaultNetworkPolicy: "deny",
	}
}

// Validate validates the bootstrap options.
func (o *BootstrapOptions) Validate() error {
	if !o.Enabled {
		return nil
	}
	if o.Servers != "" {
		if o.AdvertiseAddress == "" {
			return errors.New("advertise address is required for bootstrapping with servers")
		}
		for _, server := range strings.Split(o.Servers, ",") {
			parts := strings.Split(server, "=")
			if len(parts) != 2 {
				return fmt.Errorf("invalid bootstrap server: %s", server)
			}
		}
	}
	if o.IPv4Network == "" {
		return errors.New("bootstrap IPv4 network is required for bootstrapping")
	} else if _, err := netip.ParsePrefix(o.IPv4Network); err != nil {
		return fmt.Errorf("invalid bootstrap IPv4 network: %s", err)
	}
	return nil
}

// BindFlags binds the bootstrap options to the flag set.
func (o *BootstrapOptions) BindFlags(fl *flag.FlagSet) {
	fl.BoolVar(&o.Enabled, "bootstrap.enabled", util.GetEnvDefault(BootstrapEnabledEnvVar, "false") == "true",
		"Bootstrap the cluster.")

	fl.StringVar(&o.AdvertiseAddress, "bootstrap.advertise-address", util.GetEnvDefault(AdvertiseAddressEnvVar, ""),
		`Raft advertise address. Required when bootstrapping a new cluster,
but will be replaced with the WireGuard address after bootstrapping.`)

	fl.StringVar(&o.Servers, "bootstrap.servers", util.GetEnvDefault(BootstrapServersEnvVar, ""),
		`Comma separated list of servers to bootstrap with. This is only used if bootstrap is true.
If empty, the node will use the advertise address as the bootstrap server. If not empty,
all nodes in the list should be started with the same list configurations. If any are 
different then the first node to become leader will pick them. This can cause bootstrap
to fail when using ACLs. Servers should be in the form of <node-id>=<address> where 
address is the raft advertise address.`)

	fl.StringVar(&o.ServersGRPCPorts, "bootstrap.servers-grpc-ports", util.GetEnvDefault(BootstrapServersGRPCPortsEnvVar, ""),
		`Comma separated list of gRPC ports to bootstrap with. This is only used
if bootstrap is true. If empty, the node will use the advertise address and
locally configured gRPC port for every node in bootstrap-servers.
Ports should be in the form of <node-id>=<port>.`)

	fl.StringVar(&o.IPv4Network, "bootstrap.ipv4-network", util.GetEnvDefault(BootstrapIPv4NetworkEnvVar, "172.16.0.0/12"),
		"IPv4 network of the mesh to write to the database when bootstraping a new cluster.")

	fl.StringVar(&o.Admin, "bootstrap.admin", util.GetEnvDefault(BootstrapAdminEnvVar, "admin"),
		"Admin username to bootstrap the cluster with.")

	fl.StringVar(&o.Voters, "bootstrap.voters", util.GetEnvDefault(BootstrapVotersEnvVar, ""),
		"Comma separated list of voters to bootstrap the cluster with. bootstrap-servers are already included in this list.")

	fl.StringVar(&o.DefaultNetworkPolicy, "bootstrap.default-network-policy", util.GetEnvDefault(BootstrapDefaultNetworkPolicyEnvVar, string(NetworkPolicyDeny)),
		"Default network policy to bootstrap the cluster with.")

	fl.BoolVar(&o.Force, "bootstrap.force", util.GetEnvDefault(ForceBootstrapClusterEnvVar, "false") == "true",
		"Force bootstrapping a new cluster even if data is present.")
}
