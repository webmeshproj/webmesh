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
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshnode"
	"github.com/webmeshproj/webmesh/pkg/net/system/firewall"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/net/transport/libp2p"
	"github.com/webmeshproj/webmesh/pkg/net/transport/tcp"
	"github.com/webmeshproj/webmesh/pkg/services"
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
	// Rendezvous is the rendezvous string to use when using libp2p to bootstrap.
	Rendezvous string `koanf:"rendezvous,omitempty"`
	// RendezvousNodes is the list of node IDs to use when using libp2p to bootstrap.
	RendezvousNodes []string `koanf:"rendezvous-nodes,omitempty"`
	// RendezvousLinger is the amount of time to wait for other nodes to join when using libp2p to bootstrap.
	RendezvousLinger time.Duration `koanf:"rendezvous-linger,omitempty"`
	// PSK is the pre-shared key to use when using libp2p to bootstrap.
	PSK string `koanf:"psk,omitempty"`
}

// NewBootstrapOptions returns a new BootstrapOptions with the default values.
func NewBootstrapOptions() BootstrapOptions {
	return BootstrapOptions{
		Enabled:              false,
		ElectionTimeout:      time.Second * 3,
		Transport:            NewBootstrapTransportOptions(),
		IPv4Network:          meshnode.DefaultIPv4Network,
		MeshDomain:           meshnode.DefaultMeshDomain,
		Admin:                meshnode.DefaultMeshAdmin,
		Voters:               nil,
		DefaultNetworkPolicy: meshnode.DefaultNetworkPolicy,
		DisableRBAC:          false,
		Force:                false,
	}
}

// NewBootstrapTransportOptions returns a new BootstrapTransportOptions with the default values.
func NewBootstrapTransportOptions() BootstrapTransportOptions {
	return BootstrapTransportOptions{
		TCPAdvertiseAddress: net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", meshnode.DefaultBootstrapPort)),
		TCPListenAddress:    meshnode.DefaultBootstrapListenAddress,
		TCPConnectTimeout:   3 * time.Second,
		RendezvousLinger:    30 * time.Second,
	}
}

// BindFlags binds the bootstrap options to a flag set.
func (o *BootstrapOptions) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.BoolVar(&o.Enabled, prefix+"bootstrap.enabled", false, "Attempt to bootstrap a new cluster")
	fs.DurationVar(&o.ElectionTimeout, prefix+"bootstrap.election-timeout", time.Second*3, "Election timeout to use when bootstrapping a new cluster")
	fs.StringVar(&o.IPv4Network, prefix+"bootstrap.ipv4-network", meshnode.DefaultIPv4Network, "IPv4 network of the mesh to write to the database when bootstraping a new cluster")
	fs.StringVar(&o.MeshDomain, prefix+"bootstrap.mesh-domain", meshnode.DefaultMeshDomain, "Domain of the mesh to write to the database when bootstraping a new cluster")
	fs.StringVar(&o.Admin, prefix+"bootstrap.admin", meshnode.DefaultMeshAdmin, "User and/or node name to assign administrator privileges to when bootstraping a new cluster")
	fs.StringSliceVar(&o.Voters, prefix+"bootstrap.voters", nil, "Comma separated list of node IDs to assign voting privileges to when bootstraping a new cluster")
	fs.StringVar(&o.DefaultNetworkPolicy, prefix+"bootstrap.default-network-policy", meshnode.DefaultNetworkPolicy, "Default network policy to apply to the mesh when bootstraping a new cluster")
	fs.BoolVar(&o.DisableRBAC, prefix+"bootstrap.disable-rbac", false, "Disable RBAC when bootstrapping a new cluster")
	fs.BoolVar(&o.Force, prefix+"bootstrap.force", false, "Force new bootstrap")
	o.Transport.BindFlags(prefix, fs)
}

// BindFlags binds the bootstrap transport options to a flag set.
func (o *BootstrapTransportOptions) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.StringVar(&o.TCPAdvertiseAddress, prefix+"bootstrap.transport.tcp-advertise-address", "", "Address to advertise for raft consensus")
	fs.StringVar(&o.TCPListenAddress, prefix+"bootstrap.transport.tcp-listen-address", meshnode.DefaultBootstrapListenAddress, "Address to use when using TCP raft consensus to bootstrap")
	fs.IntVar(&o.TCPConnectionPool, prefix+"bootstrap.transport.tcp-connection-pool", 0, "Maximum number of TCP connections to maintain to other nodes")
	fs.DurationVar(&o.TCPConnectTimeout, prefix+"bootstrap.transport.tcp-connect-timeout", time.Second*3, "Maximum amount of time to wait for a TCP connection to be established")
	fs.StringToStringVar(&o.TCPServers, prefix+"bootstrap.transport.tcp-servers", nil, "Map of node IDs to raft addresses to bootstrap with")
	fs.StringToIntVar(&o.ServerGRPCPorts, prefix+"bootstrap.transport.server-grpc-ports", nil, "Map of node IDs to gRPC ports to bootstrap with")
	fs.StringVar(&o.Rendezvous, prefix+"bootstrap.transport.rendezvous", "", "Rendezvous string to use when using libp2p to bootstrap")
	fs.StringSliceVar(&o.RendezvousNodes, prefix+"bootstrap.transport.rendezvous-nodes", nil, "List of node IDs to use when using libp2p to bootstrap")
	fs.DurationVar(&o.RendezvousLinger, prefix+"bootstrap.transport.rendezvous-linger", time.Minute, "Amount of time to wait for other nodes to join when using libp2p to bootstrap")
	fs.StringVar(&o.PSK, prefix+"bootstrap.transport.psk", "", "Pre-shared key to use when using libp2p to bootstrap")
}

// Validate validates the bootstrap options.
func (o *BootstrapOptions) Validate() error {
	if !o.Enabled {
		return nil
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
	return o.Transport.Validate()
}

// Validate validates the bootstrap transport options.
func (o *BootstrapTransportOptions) Validate() error {
	if o.Rendezvous != "" || o.PSK != "" {
		// Validate libp2p options
		if len(o.RendezvousNodes) == 0 {
			return fmt.Errorf("rendezvous nodes must be set when using libp2p to bootstrap")
		}
		if o.PSK == "" {
			return fmt.Errorf("psk must be set when using libp2p to bootstrap")
		}
		if !crypto.IsValidDefaultPSK(o.PSK) {
			return fmt.Errorf("psk must be a valid %d character alphanumeric string", crypto.DefaultPSKLength)
		}
		if o.Rendezvous == "" {
			return fmt.Errorf("rendezvous must be set when using libp2p to bootstrap")
		}
		if o.RendezvousLinger <= 0 {
			return fmt.Errorf("rendezvous linger must be greater than 0")
		}
		return nil
	}
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
func (o *Config) NewBootstrapTransport(ctx context.Context, nodeID string, conn meshnode.Node, host host.Host) (transport.BootstrapTransport, error) {
	if !o.Bootstrap.Enabled {
		return transport.NewNullBootstrapTransport(), nil
	}
	t := o.Bootstrap.Transport
	if len(t.TCPServers) == 0 && len(t.PSK) == 0 && len(t.Rendezvous) == 0 {
		return transport.NewNullBootstrapTransport(), nil
	}
	if t.PSK != "" && t.Rendezvous != "" {
		if o.Discovery.ConnectTimeout > o.Bootstrap.ElectionTimeout {
			return nil, fmt.Errorf("connect timeout must be less than election timeout when using libp2p to bootstrap")
		}
		return libp2p.NewBootstrapTransport(ctx, conn.Discovery(), libp2p.BootstrapOptions{
			Rendezvous:      t.Rendezvous,
			Signer:          crypto.PSK(t.PSK),
			HostOptions:     o.Discovery.HostOptions(ctx, conn.Key()),
			Host:            host,
			ElectionTimeout: o.Bootstrap.ElectionTimeout,
			Linger:          t.RendezvousLinger,
			NodeID:          nodeID,
			NodeIDs:         t.RendezvousNodes,
		})
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
