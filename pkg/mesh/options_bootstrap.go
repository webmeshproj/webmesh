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
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/webmeshproj/webmesh/pkg/util/envutil"
)

const (
	BootstrapEnabledEnvVar              = "BOOTSTRAP_ENABLED"
	AdvertiseAddressEnvVar              = "BOOTSTRAP_ADVERTISE_ADDRESS"
	BootstrapServersEnvVar              = "BOOTSTRAP_SERVERS"
	BootstrapServersGRPCPortsEnvVar     = "BOOTSTRAP_SERVERS_GRPC_PORTS"
	BootstrapIPv4NetworkEnvVar          = "BOOTSTRAP_IPV4_NETWORK"
	BootstrapMeshDomainEnvVar           = "BOOTSTRAP_MESH_DOMAIN"
	BootstrapAdminEnvVar                = "BOOTSTRAP_ADMIN"
	BootstrapVotersEnvVar               = "BOOTSTRAP_VOTERS"
	BootstrapDefaultNetworkPolicyEnvVar = "BOOTSTRAP_DEFAULT_NETWORK_POLICY"
	BootstrapDisableRBACEnvVar          = "BOOTSTRAP_DISABLE_RBAC"
	ForceBootstrapClusterEnvVar         = "BOOTSTRAP_FORCE"
)

// BootstrapOptions are the bootstrap options.
type BootstrapOptions struct {
	// Enabled is the flag to attempt bootstrapping. If true, the node will only bootstrap a new cluster
	// if no data is found. To force a bootstrap, set Force to true.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty" toml:"enabled,omitempty" mapstructure:"enabled,omitempty"`
	// AdvertiseAddress is the initial address to advertise for raft consensus.
	AdvertiseAddress string `json:"advertise-address,omitempty" yaml:"advertise-address,omitempty" toml:"advertise-address,omitempty" mapstructure:"advertise-address,omitempty"`
	// Servers is a map of node IDs to addresses to bootstrap with. If empty, the node will use the advertise
	// address as the bootstrap server. If not empty, all nodes in the map should be started with the same
	// list configurations. If any are different then the first node to become leader will pick them. This
	// can cause bootstrap to fail when using ACLs. Servers should be in the form of <node-id>=<address>.
	Servers map[string]string `json:"servers,omitempty" yaml:"servers,omitempty" toml:"servers,omitempty" mapstructure:"servers,omitempty"`
	// ServersGRPCPorts is a map of node IDs to gRPC ports to bootstrap with. If empty, the node will use the
	// advertise address and locally configured gRPC port for every node in bootstrap-servers. Ports should
	// be in the form of <node-id>=<port>.
	ServersGRPCPorts map[string]int `json:"servers-grpc-ports,omitempty" yaml:"servers-grpc-ports,omitempty" toml:"servers-grpc-ports,omitempty" mapstructure:"servers-grpc-ports,omitempty"`
	// IPv4Network is the IPv4 network of the mesh to write to the database when bootstraping a new cluster.
	IPv4Network string `json:"ipv4-network,omitempty" yaml:"ipv4-network,omitempty" toml:"ipv4-network,omitempty" mapstructure:"ipv4-network,omitempty"`
	// MeshDomain is the domain of the mesh to write to the database when bootstraping a new cluster.
	MeshDomain string `json:"mesh-domain,omitempty" yaml:"mesh-domain,omitempty" toml:"mesh-domain,omitempty" mapstructure:"mesh-domain,omitempty"`
	// Admin is the user and/or node name to assign administrator privileges to when bootstraping a new cluster.
	Admin string `json:"admin,omitempty" yaml:"admin,omitempty" toml:"admin,omitempty" mapstructure:"admin,omitempty"`
	// Voters is a comma separated list of node IDs to assign voting privileges to when bootstraping a new cluster.
	// BootstrapServers are automatically added to this list.
	Voters string `json:"voters,omitempty" yaml:"voters,omitempty" toml:"voters,omitempty" mapstructure:"voters,omitempty"`
	// DefaultNetworkPolicy is the default network policy to apply to the mesh when bootstraping a new cluster.
	DefaultNetworkPolicy string `json:"default-network-policy,omitempty" yaml:"default-network-policy,omitempty" toml:"default-network-policy,omitempty" mapstructure:"default-network-policy,omitempty"`
	// DisableRBAC is the flag to disable RBAC when bootstrapping a new cluster.
	DisableRBAC bool `json:"disable-rbac,omitempty" yaml:"disable-rbac,omitempty" toml:"disable-rbac,omitempty" mapstructure:"disable-rbac,omitempty"`
	// Force is the force new bootstrap flag.
	Force bool `json:"force,omitempty" yaml:"force,omitempty" toml:"force,omitempty" mapstructure:"force,omitempty"`
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

const (
	DefaultIPv4Network   = "172.16.0.0/12"
	DefaultMeshDomain    = "webmesh.internal."
	DefaultAdminUser     = "admin"
	DefaultNetworkPolicy = NetworkPolicyAccept
)

// NewBootstrapOptions creates a new BootstrapOptions.
func NewBootstrapOptions() *BootstrapOptions {
	return &BootstrapOptions{
		Enabled:              false,
		IPv4Network:          DefaultIPv4Network,
		MeshDomain:           DefaultMeshDomain,
		Admin:                DefaultAdminUser,
		DefaultNetworkPolicy: string(DefaultNetworkPolicy),
	}
}

// Validate validates the bootstrap options.
func (o *BootstrapOptions) Validate() error {
	if o == nil || !o.Enabled {
		return nil
	}
	if len(o.Servers) == 0 && os.Getenv(BootstrapServersEnvVar) != "" {
		// Parse the servers from the environment variable.
		o.Servers = make(map[string]string)
		for _, server := range strings.Split(os.Getenv(BootstrapServersEnvVar), ",") {
			parts := strings.Split(server, "=")
			if len(parts) != 2 {
				return fmt.Errorf("invalid bootstrap server: %s", server)
			}
			o.Servers[parts[0]] = parts[1]
		}
	}
	if len(o.ServersGRPCPorts) == 0 && os.Getenv(BootstrapServersGRPCPortsEnvVar) != "" {
		// Parse the servers from the environment variable.
		o.ServersGRPCPorts = make(map[string]int)
		for _, server := range strings.Split(os.Getenv(BootstrapServersGRPCPortsEnvVar), ",") {
			parts := strings.Split(server, "=")
			if len(parts) != 2 {
				return fmt.Errorf("invalid bootstrap server gRPC port: %s", server)
			}
			port, err := strconv.Atoi(parts[1])
			if err != nil {
				return fmt.Errorf("invalid bootstrap server gRPC port: %s", server)
			}
			o.ServersGRPCPorts[parts[0]] = port
		}
	}
	if len(o.Servers) > 0 && o.AdvertiseAddress == "" {
		return errors.New("advertise address is required for bootstrapping with servers")
	}
	if o.IPv4Network == "" {
		return errors.New("bootstrap IPv4 network is required for bootstrapping")
	} else if _, err := netip.ParsePrefix(o.IPv4Network); err != nil {
		return fmt.Errorf("invalid bootstrap IPv4 network: %s", err)
	}
	if o.MeshDomain == "" {
		return errors.New("bootstrap mesh domain is required for bootstrapping")
	} else if !strings.HasSuffix(o.MeshDomain, ".") {
		// Append the period to the domain if it's not there.
		o.MeshDomain = o.MeshDomain + "."
	}
	return nil
}

// BindFlags binds the bootstrap options to the flag set.
func (o *BootstrapOptions) BindFlags(fl *flag.FlagSet, prefix ...string) {
	var p string
	if len(prefix) > 0 {
		p = strings.Join(prefix, ".") + "."
	}
	fl.BoolVar(&o.Enabled, p+"bootstrap.enabled", envutil.GetEnvDefault(BootstrapEnabledEnvVar, "false") == "true",
		"Bootstrap the cluster.")
	fl.StringVar(&o.AdvertiseAddress, p+"bootstrap.advertise-address", envutil.GetEnvDefault(AdvertiseAddressEnvVar, ""),
		`Raft advertise address. Required when bootstrapping a new cluster,
but will be replaced with the WireGuard address after bootstrapping.`)
	fl.Func(p+"bootstrap.servers", `Comma separated list of servers to bootstrap with. This is only used if bootstrap is true.
	If empty, the node will use the advertise address as the bootstrap server. If not empty,
	all nodes in the list should be started with the same list configurations. If any are 
	different then the first node to become leader will pick them. This can cause bootstrap
	to fail when using ACLs. Servers should be in the form of <node-id>=<address> where 
	address is the raft advertise address.`,
		func(val string) error {
			o.Servers = make(map[string]string)
			for _, server := range strings.Split(val, ",") {
				parts := strings.Split(server, "=")
				if len(parts) != 2 {
					return fmt.Errorf("invalid bootstrap server: %s", server)
				}
				o.Servers[parts[0]] = parts[1]
			}
			return nil
		})
	fl.Func(p+"bootstrap.servers-grpc-ports",
		`Comma separated list of gRPC ports to bootstrap with. This is only used
if bootstrap is true. If empty, the node will use the advertise address and
locally configured gRPC port for every node in bootstrap-servers.
Ports should be in the form of <node-id>=<port>.`,
		func(val string) error {
			o.ServersGRPCPorts = make(map[string]int)
			for _, server := range strings.Split(val, ",") {
				parts := strings.Split(server, "=")
				if len(parts) != 2 {
					return fmt.Errorf("invalid bootstrap server gRPC port: %s", server)
				}
				port, err := strconv.Atoi(parts[1])
				if err != nil {
					return fmt.Errorf("invalid bootstrap server gRPC port: %s", server)
				}
				o.ServersGRPCPorts[parts[0]] = port
			}
			return nil
		})
	fl.StringVar(&o.IPv4Network, p+"bootstrap.ipv4-network", envutil.GetEnvDefault(BootstrapIPv4NetworkEnvVar, "172.16.0.0/12"),
		"IPv4 network of the mesh to write to the database when bootstraping a new cluster.")
	fl.StringVar(&o.MeshDomain, p+"bootstrap.mesh-domain", envutil.GetEnvDefault(BootstrapMeshDomainEnvVar, "webmesh.internal"),
		"Domain of the mesh to write to the database when bootstraping a new cluster.")
	fl.StringVar(&o.Admin, p+"bootstrap.admin", envutil.GetEnvDefault(BootstrapAdminEnvVar, "admin"),
		"Admin username to bootstrap the cluster with.")
	fl.StringVar(&o.Voters, p+"bootstrap.voters", envutil.GetEnvDefault(BootstrapVotersEnvVar, ""),
		"Comma separated list of voters to bootstrap the cluster with. bootstrap-servers are already included in this list.")
	fl.StringVar(&o.DefaultNetworkPolicy, p+"bootstrap.default-network-policy", envutil.GetEnvDefault(BootstrapDefaultNetworkPolicyEnvVar, string(NetworkPolicyDeny)),
		"Default network policy to bootstrap the cluster with.")
	fl.BoolVar(&o.DisableRBAC, p+"bootstrap.disable-rbac", envutil.GetEnvDefault(BootstrapDisableRBACEnvVar, "false") == "true",
		"Disable RBAC when bootstrapping a new cluster.")
	fl.BoolVar(&o.Force, p+"bootstrap.force", envutil.GetEnvDefault(ForceBootstrapClusterEnvVar, "false") == "true",
		"Force bootstrapping a new cluster even if data is present.")
}

// DeepCopy returns a deep copy of the bootstrap options.
func (o *BootstrapOptions) DeepCopy() *BootstrapOptions {
	if o == nil {
		return nil
	}
	out := &BootstrapOptions{
		Enabled:              o.Enabled,
		AdvertiseAddress:     o.AdvertiseAddress,
		Servers:              make(map[string]string),
		ServersGRPCPorts:     make(map[string]int),
		IPv4Network:          o.IPv4Network,
		MeshDomain:           o.MeshDomain,
		Admin:                o.Admin,
		Voters:               o.Voters,
		DefaultNetworkPolicy: o.DefaultNetworkPolicy,
		Force:                o.Force,
	}
	for k, v := range o.Servers {
		out.Servers[k] = v
	}
	for k, v := range o.ServersGRPCPorts {
		out.ServersGRPCPorts[k] = v
	}
	return out
}
