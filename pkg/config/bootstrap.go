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
	"net/netip"
	"time"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshnet/netutil"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system/firewall"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport/libp2p"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport/tcp"
	"github.com/webmeshproj/webmesh/pkg/meshnode"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// BootstrapOptions are options for bootstrapping a new mesh.
type BootstrapOptions struct {
	// Enabled is the flag to attempt bootstrapping. If true, the node will only bootstrap a new cluster
	// if no data is found. To force a bootstrap, set Force to true.
	Enabled bool `koanf:"enabled,omitempty"`
	// ElectionTimeout is the election timeout to use when bootstrapping a new cluster.
	ElectionTimeout time.Duration `koanf:"election-timeout,omitempty"`
	// Transport are the bootstrap transport options
	Transport BootstrapTransportOptions `koanf:"transport,omitempty"`
	// IPv4Network is the IPv4 network of the mesh to write to the database when bootstraping a new cluster.
	IPv4Network string `koanf:"ipv4-network,omitempty"`
	// IPv6Network is the IPv6 network of the mesh to write to the database when bootstraping a new cluster.
	// If left unset, one will be generated. This must be a /32 prefix.
	IPv6Network string `koanf:"ipv6-network,omitempty"`
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

// BootstrapTransportOptions are options for the bootstrap transport.
type BootstrapTransportOptions struct {
	// TCPAdvertiseAddress is the initial address to advertise for raft consensus.
	TCPAdvertiseAddress string `koanf:"tcp-advertise-address,omitempty"`
	// TCPListenAddress is the initial address to use when using TCP raft consensus to bootstrap.
	TCPListenAddress string `koanf:"tcp-listen-address,omitempty"`
	// TCPServers is a map of node IDs to addresses to bootstrap with. If empty, the node will use the advertise
	// address as the bootstrap server. If not empty, all nodes in the map should be started with the same
	// list configurations. If any are different then the first node to become leader will pick them. This
	// can cause bootstrap to fail when using ACLs. Servers should be in the form of <node-id>=<address>.
	TCPServers map[string]string `koanf:"tcp-servers,omitempty"`
	// TCPConnectionPool is the maximum number of TCP connections to maintain to other nodes.
	TCPConnectionPool int `koanf:"tcp-connection-pool,omitempty"`
	// TCPConnectTimeout is the maximum amount of time to wait for a TCP connection to be established.
	TCPConnectTimeout time.Duration `koanf:"tcp-connect-timeout,omitempty"`
	// ServerGRPCPorts is a map of node IDs to gRPC ports to bootstrap with. If empty, the node will use the
	// advertise address and locally configured gRPC port for every node in bootstrap-servers. Ports should
	// be in the form of <node-id>=<port>.
	ServerGRPCPorts map[string]int `koanf:"server-grpc-ports,omitempty"`
}

// NewBootstrapOptions returns a new BootstrapOptions with the default values.
func NewBootstrapOptions() BootstrapOptions {
	return BootstrapOptions{
		Enabled:              false,
		ElectionTimeout:      time.Second * 3,
		Transport:            NewBootstrapTransportOptions(),
		IPv4Network:          storage.DefaultIPv4Network,
		IPv6Network:          "",
		MeshDomain:           storage.DefaultMeshDomain,
		Admin:                storage.DefaultMeshAdmin,
		Voters:               nil,
		DefaultNetworkPolicy: storage.DefaultNetworkPolicy,
		DisableRBAC:          false,
		Force:                false,
	}
}

// NewBootstrapTransportOptions returns a new BootstrapTransportOptions with the default values.
func NewBootstrapTransportOptions() BootstrapTransportOptions {
	return BootstrapTransportOptions{
		TCPAdvertiseAddress: storage.DefaultBootstrapAdvertiseAddress,
		TCPListenAddress:    storage.DefaultBootstrapListenAddress,
		TCPServers:          map[string]string{},
		TCPConnectionPool:   0,
		TCPConnectTimeout:   3 * time.Second,
		ServerGRPCPorts:     map[string]int{},
	}
}

// BindFlags binds the bootstrap options to a flag set.
func (o *BootstrapOptions) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.BoolVar(&o.Enabled, prefix+"enabled", o.Enabled, "Attempt to bootstrap a new cluster")
	fs.DurationVar(&o.ElectionTimeout, prefix+"election-timeout", o.ElectionTimeout, "Election timeout to use when bootstrapping a new cluster")
	fs.StringVar(&o.IPv4Network, prefix+"ipv4-network", o.IPv4Network, "IPv4 network of the mesh to write to the database when bootstraping a new cluster")
	fs.StringVar(&o.IPv6Network, prefix+"ipv6-network", o.IPv6Network, "IPv6 network of the mesh to write to the database when bootstraping a new cluster, if left unset one will be generated")
	fs.StringVar(&o.MeshDomain, prefix+"mesh-domain", o.MeshDomain, "Domain of the mesh to write to the database when bootstraping a new cluster")
	fs.StringVar(&o.Admin, prefix+"admin", o.Admin, "User and/or node name to assign administrator privileges to when bootstraping a new cluster")
	fs.StringSliceVar(&o.Voters, prefix+"voters", o.Voters, "Comma separated list of node IDs to assign voting privileges to when bootstraping a new cluster")
	fs.StringVar(&o.DefaultNetworkPolicy, prefix+"default-network-policy", o.DefaultNetworkPolicy, "Default network policy to apply to the mesh when bootstraping a new cluster")
	fs.BoolVar(&o.DisableRBAC, prefix+"disable-rbac", o.DisableRBAC, "Disable RBAC when bootstrapping a new cluster")
	fs.BoolVar(&o.Force, prefix+"force", o.Force, "Force new bootstrap")
	o.Transport.BindFlags(prefix+"transport.", fs)
}

// BindFlags binds the bootstrap transport options to a flag set.
func (o *BootstrapTransportOptions) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.StringVar(&o.TCPAdvertiseAddress, prefix+"tcp-advertise-address", o.TCPAdvertiseAddress, "Address to advertise for raft consensus")
	fs.StringVar(&o.TCPListenAddress, prefix+"tcp-listen-address", o.TCPListenAddress, "Address to use when using TCP raft consensus to bootstrap")
	fs.IntVar(&o.TCPConnectionPool, prefix+"tcp-connection-pool", o.TCPConnectionPool, "Maximum number of TCP connections to maintain to other nodes")
	fs.DurationVar(&o.TCPConnectTimeout, prefix+"tcp-connect-timeout", o.TCPConnectTimeout, "Maximum amount of time to wait for a TCP connection to be established")
	fs.StringToStringVar(&o.TCPServers, prefix+"tcp-servers", o.TCPServers, "Map of node IDs to raft addresses to bootstrap with")
	fs.StringToIntVar(&o.ServerGRPCPorts, prefix+"server-grpc-ports", o.ServerGRPCPorts, "Map of node IDs to gRPC ports to bootstrap with")
}

// Validate validates the bootstrap options.
func (o *BootstrapOptions) Validate() error {
	if o == nil || !o.Enabled {
		return nil
	}
	if o.IPv4Network == "" {
		return fmt.Errorf("ipv4 network must be set when bootstrapping")
	}
	if ip, _, err := net.ParseCIDR(o.IPv4Network); err != nil {
		return fmt.Errorf("ipv4 network must be a valid CIDR")
	} else if ip.To4() == nil {
		return fmt.Errorf("ipv4 network must be a valid IPv4 CIDR")
	}
	if o.IPv6Network != "" {
		prefix, err := netip.ParsePrefix(o.IPv6Network)
		if err != nil {
			return fmt.Errorf("ipv6 network must be a valid CIDR")
		}
		if prefix.Bits() != netutil.DefaultULABits {
			return fmt.Errorf("ipv6 network must be a /%d prefix", netutil.DefaultULABits)
		}
	}
	if o.MeshDomain == "" {
		return fmt.Errorf("mesh domain must be set when bootstrapping")
	}
	if o.Admin == "" {
		return fmt.Errorf("admin must be set when bootstrapping")
	}
	if !types.IsValidNodeID(o.Admin) {
		return fmt.Errorf("admin must be a valid node or user name")
	}
	if o.DefaultNetworkPolicy == "" {
		return fmt.Errorf("default network policy must be set when bootstrapping")
	}
	if o.DefaultNetworkPolicy != string(firewall.PolicyAccept) && o.DefaultNetworkPolicy != string(firewall.PolicyDrop) {
		return fmt.Errorf("default network policy must be accept or drop")
	}
	return o.Transport.Validate()
}

// Validate validates the bootstrap transport options.
func (o BootstrapTransportOptions) Validate() error {
	// Validate TCP options
	if o.TCPAdvertiseAddress == "" {
		return fmt.Errorf("advertise address must be set when bootstrapping")
	}
	if o.TCPListenAddress == "" {
		return fmt.Errorf("listen address must be set when bootstrapping")
	}
	_, _, err := net.SplitHostPort(o.TCPAdvertiseAddress)
	if err != nil {
		return fmt.Errorf("advertise address must be a valid host:port")
	}
	_, _, err = net.SplitHostPort(o.TCPListenAddress)
	if err != nil {
		return fmt.Errorf("listen address must be a valid host:port")
	}
	return nil
}

// NewBootstrapTransport returns the bootstrap transport for the configuration.
func (o *Config) NewBootstrapTransport(ctx context.Context, nodeID string, conn meshnode.Node, host libp2p.Host) (transport.BootstrapTransport, error) {
	if !o.Bootstrap.Enabled {
		return transport.NewNullBootstrapTransport(), nil
	}
	t := o.Bootstrap.Transport
	if len(t.TCPServers) == 0 {
		return transport.NewNullBootstrapTransport(), nil
	}
	return tcp.NewBootstrapTransport(tcp.BootstrapTransportOptions{
		NodeID:          nodeID,
		Addr:            t.TCPListenAddress,
		Advertise:       t.TCPAdvertiseAddress,
		MaxPool:         t.TCPConnectionPool,
		Timeout:         t.TCPConnectTimeout,
		ElectionTimeout: o.Bootstrap.ElectionTimeout,
		Credentials:     conn.Credentials(),
		Peers: func() map[string]tcp.BootstrapPeer {
			if t.TCPServers == nil {
				return nil
			}
			peers := make(map[string]tcp.BootstrapPeer)
			for id, addr := range t.TCPServers {
				if id == nodeID {
					continue
				}
				peerID := id
				nodeAddr := addr
				nodeHost, _, err := net.SplitHostPort(nodeAddr)
				if err != nil {
					// We should have caught this earlier
					continue
				}
				// Deterine what their join address will be
				var joinAddr string
				if port, ok := t.ServerGRPCPorts[peerID]; ok {
					joinAddr = net.JoinHostPort(nodeHost, fmt.Sprintf("%d", port))
				} else {
					// Assume the default gRPC port
					joinAddr = net.JoinHostPort(nodeHost, fmt.Sprintf("%d", services.DefaultGRPCPort))
				}
				peers[peerID] = tcp.BootstrapPeer{
					NodeID:        peerID,
					AdvertiseAddr: nodeAddr,
					DialAddr:      joinAddr,
				}
			}
			return peers
		}(),
	}), nil
}
