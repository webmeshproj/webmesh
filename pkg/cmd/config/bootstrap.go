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
	"net"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/net/system/firewall"
)

// BootstrapOptions are options for bootstrapping a new mesh.
type BootstrapOptions struct {
	// Enabled is the flag to attempt bootstrapping. If true, the node will only bootstrap a new cluster
	// if no data is found. To force a bootstrap, set Force to true.
	Enabled bool `koanf:"enabled,omitempty"`
	// AdvertiseAddress is the initial address to advertise for raft consensus.
	AdvertiseAddress string `koanf:"advertise-address,omitempty"`
	// ListenAddress is the initial address to use when using TCP raft consensus to bootstrap.
	ListenAddress string `koanf:"listen-address,omitempty"`
	// Servers is a map of node IDs to addresses to bootstrap with. If empty, the node will use the advertise
	// address as the bootstrap server. If not empty, all nodes in the map should be started with the same
	// list configurations. If any are different then the first node to become leader will pick them. This
	// can cause bootstrap to fail when using ACLs. Servers should be in the form of <node-id>=<address>.
	Servers map[string]string `koanf:"servers,omitempty"`
	// ServersGRPCPorts is a map of node IDs to gRPC ports to bootstrap with. If empty, the node will use the
	// advertise address and locally configured gRPC port for every node in bootstrap-servers. Ports should
	// be in the form of <node-id>=<port>.
	ServersGRPCPorts map[string]int `koanf:"servers-grpc-ports,omitempty"`
	// IPv4Network is the IPv4 network of the mesh to write to the database when bootstraping a new cluster.
	IPv4Network string `koanf:"ipv4-network,omitempty"`
	// MeshDomain is the domain of the mesh to write to the database when bootstraping a new cluster.
	MeshDomain string `koanf:"mesh-domain,omitempty"`
	// Admin is the user and/or node name to assign administrator privileges to when bootstraping a new cluster.
	Admin string `koanf:"admin,omitempty"`
	// Voters is a comma separated list of node IDs to assign voting privileges to when bootstraping a new cluster.
	// BootstrapServers are automatically added to this list.
	Voters []string `koanf:"voters,omitempty"`
	// DefaultNetworkPolicy is the default network policy to apply to the mesh when bootstraping a new cluster.
	DefaultNetworkPolicy string `koanf:"default-network-policy,omitempty"`
	// DisableRBAC is the flag to disable RBAC when bootstrapping a new cluster.
	DisableRBAC bool `koanf:"disable-rbac,omitempty"`
	// Force is the force new bootstrap flag.
	Force bool `koanf:"force,omitempty"`
}

// BindFlags binds the bootstrap options to a flag set.
func (o *BootstrapOptions) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.BoolVar(&o.Enabled, prefix+"bootstrap.enabled", false, "Attempt to bootstrap a new cluster")
	fs.StringVar(&o.AdvertiseAddress, prefix+"bootstrap.advertise-address", "", "Address to advertise for raft consensus")
	fs.StringVar(&o.ListenAddress, prefix+"bootstrap.listen-address", mesh.DefaultBootstrapListenAddress, "Address to use when using TCP raft consensus to bootstrap")
	fs.StringToStringVar(&o.Servers, prefix+"bootstrap.servers", nil, "Map of node IDs to raft addresses to bootstrap with")
	fs.StringToIntVar(&o.ServersGRPCPorts, prefix+"bootstrap.servers-grpc-ports", nil, "Map of node IDs to gRPC ports to bootstrap with")
	fs.StringVar(&o.IPv4Network, prefix+"bootstrap.ipv4-network", mesh.DefaultIPv4Network, "IPv4 network of the mesh to write to the database when bootstraping a new cluster")
	fs.StringVar(&o.MeshDomain, prefix+"bootstrap.mesh-domain", mesh.DefaultMeshDomain, "Domain of the mesh to write to the database when bootstraping a new cluster")
	fs.StringVar(&o.Admin, prefix+"bootstrap.admin", mesh.DefaultMeshAdmin, "User and/or node name to assign administrator privileges to when bootstraping a new cluster")
	fs.StringSliceVar(&o.Voters, prefix+"bootstrap.voters", nil, "Comma separated list of node IDs to assign voting privileges to when bootstraping a new cluster")
	fs.StringVar(&o.DefaultNetworkPolicy, prefix+"bootstrap.default-network-policy", mesh.DefaultNetworkPolicy, "Default network policy to apply to the mesh when bootstraping a new cluster")
	fs.BoolVar(&o.DisableRBAC, prefix+"bootstrap.disable-rbac", false, "Disable RBAC when bootstrapping a new cluster")
	fs.BoolVar(&o.Force, prefix+"bootstrap.force", false, "Force new bootstrap")
}

// Validate validates the bootstrap options.
func (o *BootstrapOptions) Validate() error {
	if !o.Enabled {
		return nil
	}
	if o.AdvertiseAddress == "" {
		return fmt.Errorf("advertise address must be set when bootstrapping")
	}
	if o.ListenAddress == "" {
		return fmt.Errorf("listen address must be set when bootstrapping")
	}
	_, _, err := net.SplitHostPort(o.AdvertiseAddress)
	if err != nil {
		return fmt.Errorf("advertise address must be a valid host:port")
	}
	_, _, err = net.SplitHostPort(o.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen address must be a valid host:port")
	}
	if o.IPv4Network == "" {
		return fmt.Errorf("ipv4 network must be set when bootstrapping")
	}
	if _, _, err := net.ParseCIDR(o.IPv4Network); err != nil {
		return fmt.Errorf("ipv4 network must be a valid CIDR")
	}
	if o.MeshDomain == "" {
		return fmt.Errorf("mesh domain must be set when bootstrapping")
	}
	if o.Admin == "" {
		return fmt.Errorf("admin must be set when bootstrapping")
	}
	if o.DefaultNetworkPolicy == "" {
		return fmt.Errorf("default network policy must be set when bootstrapping")
	}
	if o.DefaultNetworkPolicy != string(firewall.PolicyAccept) && o.DefaultNetworkPolicy != string(firewall.PolicyDrop) {
		return fmt.Errorf("default network policy must be accept or drop")
	}
	return nil
}
