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
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/webmeshproj/webmesh/pkg/campfire"
	"github.com/webmeshproj/webmesh/pkg/util"
)

const (
	NodeIDEnvVar                  = "MESH_NODE_ID"
	ZoneAwarenessIDEnvVar         = "MESH_ZONE_AWARENESS_ID"
	JoinAddressEnvVar             = "MESH_JOIN_ADDRESS"
	JoinCampfirePSKEnvVar         = "MESH_JOIN_CAMPFIRE_PSK"
	JoinCampfireTURNServersEnvVar = "MESH_JOIN_CAMPFIRE_TURN_SERVERS"
	WaitCampfirePSKEnvVar         = "MESH_WAIT_CAMPFIRE_PSK"
	WaitCampfireTURNServersEnvVar = "MESH_WAIT_CAMPFIRE_TURN_SERVERS"
	PeerDiscoveryAddressesEnvVar  = "MESH_PEER_DISCOVERY_ADDRESSES"
	JoinAsVoterEnvVar             = "MESH_JOIN_AS_VOTER"
	MaxJoinRetriesEnvVar          = "MESH_MAX_JOIN_RETRIES"
	JoinTimeoutEnvVar             = "MESH_JOIN_TIMEOUT"
	GRPCAdvertisePortEnvVar       = "MESH_GRPC_ADVERTISE_PORT"
	DNSAdvertisePortEnvVar        = "MESH_MESHDNS_ADVERTISE_PORT"
	UseMeshDNSEnvVar              = "MESH_USE_MESHDNS"
	PrimaryEndpointEnvVar         = "MESH_PRIMARY_ENDPOINT"
	NodeRoutesEnvVar              = "MESH_ROUTES"
	NodeDirectPeersEnvVar         = "MESH_DIRECT_PEERS"
	HeartbeatPurgeThresholdEnvVar = "MESH_HEARTBEAT_PURGE_THRESHOLD"
	NoIPv4EnvVar                  = "MESH_NO_IPV4"
	NoIPv6EnvVar                  = "MESH_NO_IPV6"
)

// MeshOptions are the options for participating in a mesh.
type MeshOptions struct {
	// NodeID is the node ID.
	NodeID string `json:"node-id,omitempty" yaml:"node-id,omitempty" toml:"node-id,omitempty"`
	// ZoneAwarenessID is the zone awareness ID.
	ZoneAwarenessID string `json:"zone-awareness-id,omitempty" yaml:"zone-awareness-id,omitempty" toml:"zone-awareness-id,omitempty"`
	// JoinAddress is the address of a node to join.
	JoinAddress string `json:"join-address,omitempty" yaml:"join-address,omitempty" toml:"join-address,omitempty"`
	// JoinCampfirePSK is the PSK to use for joining via the campfire protocol.
	JoinCampfirePSK string `json:"join-campfire-psk,omitempty" yaml:"join-campfire-psk,omitempty" toml:"join-campfire-psk,omitempty"`
	// JoinCampfireTURNServers is the TURN servers to use for joining via the campfire protocol.
	JoinCampfireTURNServers []string `json:"join-campfire-turn-servers,omitempty" yaml:"join-campfire-turn-servers,omitempty" toml:"join-campfire-turn-servers,omitempty"`
	// WaitCampfirePSK is the PSK for offering others to join via the campfire protocol.
	WaitCampfirePSK string `json:"wait-campfire-psk,omitempty" yaml:"wait-campfire-psk,omitempty" toml:"wait-campfire-psk,omitempty"`
	// WaitCampfireTURNServers is the TURN servers for offering others to join via the campfire protocol.
	WaitCampfireTURNServers []string `json:"wait-campfire-turn-servers,omitempty" yaml:"wait-campfire-turn-servers,omitempty" toml:"wait-campfire-turn-servers,omitempty"`
	// PeerDiscoveryAddresses are the addresses to use for peer discovery.
	PeerDiscoveryAddresses []string `json:"peer-discovery-addresses,omitempty" yaml:"peer-discovery-addresses,omitempty" toml:"peer-discovery-addresses,omitempty"`
	// MaxJoinRetries is the maximum number of join retries.
	MaxJoinRetries int `json:"max-join-retries,omitempty" yaml:"max-join-retries,omitempty" toml:"max-join-retries,omitempty"`
	// Voter is true if the node should be a voter.
	JoinAsVoter bool `json:"voter,omitempty" yaml:"voter,omitempty" toml:"voter,omitempty"`
	// PrimaryEndpoint is the primary endpoint to advertise when joining.
	PrimaryEndpoint string `json:"primary-endpoint,omitempty" yaml:"primary-endpoint,omitempty" toml:"primary-endpoint,omitempty"`
	// Routes are additional routes to advertise to the mesh. These routes are advertised to all peers.
	// If the node is not allowed to put routes in the mesh, the node will be unable to join.
	Routes []string `json:"routes,omitempty" yaml:"routes,omitempty" toml:"routes,omitempty"`
	// DirectPeers are peers to request direct edges to. If the node is not allowed to create edges
	// and data channels, the node will be unable to join.
	DirectPeers []string `json:"direct-peers,omitempty" yaml:"direct-peers,omitempty" toml:"direct-peers,omitempty"`
	// GRPCAdvertisePort is the port to advertise for gRPC.
	GRPCAdvertisePort int `json:"grpc-advertise-port,omitempty" yaml:"grpc-advertise-port,omitempty" toml:"grpc-advertise-port,omitempty"`
	// MeshDNSAdvertisePort is the port to advertise for DNS.
	MeshDNSAdvertisePort int `json:"meshdns-advertise-port,omitempty" yaml:"meshdns-advertise-port,omitempty" toml:"meshdns-advertise-port,omitempty"`
	// UseMeshDNS indicates whether to set mesh DNS servers in the system configuration.
	UseMeshDNS bool `json:"use-meshdns,omitempty" yaml:"use-meshdns,omitempty" toml:"use-meshdns,omitempty"`
	// HeartbeatPurgeThreshold is the threshold of failed heartbeats for purging a peer.
	HeartbeatPurgeThreshold int `json:"heartbeat-purge-threshold,omitempty" yaml:"heartbeat-purge-threshold,omitempty" toml:"heartbeat-purge-threshold,omitempty"`
	// NoIPv4 disables IPv4 usage.
	NoIPv4 bool `json:"no-ipv4,omitempty" yaml:"no-ipv4,omitempty" toml:"no-ipv4,omitempty"`
	// NoIPv6 disables IPv6 usage.
	NoIPv6 bool `json:"no-ipv6,omitempty" yaml:"no-ipv6,omitempty" toml:"no-ipv6,omitempty"`
}

// NewMeshOptions creates a new MeshOptions with default values. If the grpcPort
// is 0, the default is used.
func NewMeshOptions(grpcPort int) *MeshOptions {
	if grpcPort == 0 {
		grpcPort = DefaultGRPCPort
	}
	return &MeshOptions{
		PeerDiscoveryAddresses: func() []string {
			if val, ok := os.LookupEnv(PeerDiscoveryAddressesEnvVar); ok {
				return strings.Split(val, ",")
			}
			return nil
		}(),
		Routes: func() []string {
			if val, ok := os.LookupEnv(NodeRoutesEnvVar); ok {
				return strings.Split(val, ",")
			}
			return nil
		}(),
		DirectPeers: func() []string {
			if val, ok := os.LookupEnv(NodeDirectPeersEnvVar); ok {
				return strings.Split(val, ",")
			}
			return nil
		}(),
		JoinCampfireTURNServers: func() []string {
			if val, ok := os.LookupEnv(JoinCampfireTURNServersEnvVar); ok {
				return strings.Split(val, ",")
			}
			return nil
		}(),
		WaitCampfireTURNServers: func() []string {
			if val, ok := os.LookupEnv(WaitCampfireTURNServersEnvVar); ok {
				return strings.Split(val, ",")
			}
			return nil
		}(),
		MaxJoinRetries:    10,
		GRPCAdvertisePort: grpcPort,
	}
}

const hostnameFlagDefault = "<hostname>"

// BindFlags binds the MeshOptions to a flag set.
func (o *MeshOptions) BindFlags(fl *flag.FlagSet, prefix ...string) {
	var p string
	if len(prefix) > 0 {
		p = strings.Join(prefix, ".") + "."
	}
	fl.StringVar(&o.NodeID, p+"mesh.node-id", util.GetEnvDefault(NodeIDEnvVar, hostnameFlagDefault),
		`Store node ID. If not set, the ID comes from the following decision tree.
1. If mTLS is enabled, the node ID is the CN of the client certificate.
2. If mTLS is not enabled, the node ID is the hostname of the machine.
3. If the hostname is not available, the node ID is a random UUID (should only be used for testing).`)
	fl.StringVar(&o.ZoneAwarenessID, p+"mesh.zone-awareness-id", util.GetEnvDefault(ZoneAwarenessIDEnvVar, ""),
		"Zone awareness ID. If set, the server will prioritize peer endpoints in the same zone.")
	fl.StringVar(&o.JoinAddress, p+"mesh.join-address", util.GetEnvDefault(JoinAddressEnvVar, ""),
		"Address of a node to join.")
	fl.Func(p+"mesh.peer-discovery-addresses", "Addresses to use for peer discovery.", func(val string) error {
		o.PeerDiscoveryAddresses = append(o.PeerDiscoveryAddresses, strings.Split(val, ",")...)
		return nil
	})
	fl.StringVar(&o.JoinCampfirePSK, p+"mesh.join-campfire-psk", util.GetEnvDefault(JoinCampfirePSKEnvVar, ""),
		"Campfire PSK to use for joining.")
	fl.Func(p+"mesh.join-campfire-turn-servers", "Campfire TURN servers to use for joining.", func(val string) error {
		o.JoinCampfireTURNServers = append(o.JoinCampfireTURNServers, strings.Split(val, ",")...)
		return nil
	})
	fl.StringVar(&o.WaitCampfirePSK, p+"mesh.wait-campfire-psk", util.GetEnvDefault(WaitCampfirePSKEnvVar, ""),
		"Campfire PSK to use for waiting.")
	fl.Func(p+"mesh.wait-campfire-turn-servers", "Campfire TURN servers to use for waiting.", func(val string) error {
		o.WaitCampfireTURNServers = append(o.WaitCampfireTURNServers, strings.Split(val, ",")...)
		return nil
	})
	fl.IntVar(&o.MaxJoinRetries, p+"mesh.max-join-retries", util.GetEnvIntDefault(MaxJoinRetriesEnvVar, 10),
		"Maximum number of join retries.")
	fl.BoolVar(&o.JoinAsVoter, p+"mesh.join-as-voter", util.GetEnvDefault(JoinAsVoterEnvVar, "false") == "true",
		"Join the cluster as a voter. Default behavior is to join as an observer.")
	fl.IntVar(&o.GRPCAdvertisePort, p+"mesh.grpc-advertise-port", util.GetEnvIntDefault(GRPCAdvertisePortEnvVar, 8443),
		"GRPC advertise port.")
	fl.IntVar(&o.MeshDNSAdvertisePort, p+"mesh.meshdns-advertise-port", util.GetEnvIntDefault(DNSAdvertisePortEnvVar, 0),
		"DNS advertise port. This is set automatically when advertising is enabled and the mesh-dns server is running. Default is 0 (disabled).")
	fl.BoolVar(&o.UseMeshDNS, p+"mesh.use-meshdns", util.GetEnvDefault(UseMeshDNSEnvVar, "false") == "true",
		"Set mesh DNS servers to the system configuration. If a local server is running, this will use the local server.")
	fl.StringVar(&o.PrimaryEndpoint, p+"mesh.primary-endpoint", util.GetEnvDefault(PrimaryEndpointEnvVar, ""),
		`The primary endpoint to broadcast when joining a cluster.
This is only necessary if the node intends on being publicly accessible.`)
	fl.Func(p+"mesh.routes", `Comma separated list of additional routes to advertise to the mesh.
	These routes are advertised to all peers. If the node is not allowed
	to put routes in the mesh, the node will be unable to join.`, func(s string) error {
		o.Routes = append(o.Routes, strings.Split(s, ",")...)
		return nil
	})
	fl.Func(p+"mesh.direct-peers", `Comma separated list of peers to request direct edges to.
	If the node is not allowed to create edges and data channels, the node will be unable to join.`, func(s string) error {
		o.DirectPeers = append(o.DirectPeers, strings.Split(s, ",")...)
		return nil
	})
	fl.IntVar(&o.HeartbeatPurgeThreshold, p+"mesh.heartbeat-purge-threshold", util.GetEnvIntDefault(HeartbeatPurgeThresholdEnvVar, 0),
		"Threshold of failed heartbeats for purging a peer. Default is 0 (disabled).")
	fl.BoolVar(&o.NoIPv4, p+"mesh.no-ipv4", util.GetEnvDefault(NoIPv4EnvVar, "false") == "true",
		"Do not request IPv4 assignments when joining.")
	fl.BoolVar(&o.NoIPv6, p+"mesh.no-ipv6", util.GetEnvDefault(NoIPv6EnvVar, "false") == "true",
		"Do not request IPv6 assignments when joining.")
}

// Validate validates the MeshOptions.
func (o *MeshOptions) Validate() error {
	if o == nil {
		return fmt.Errorf("mesh options cannot be empty")
	}
	if o.NoIPv4 && o.NoIPv6 {
		return fmt.Errorf("cannot disable both IPv4 and IPv6")
	}
	if o.JoinCampfirePSK != "" && len(o.JoinCampfirePSK) != campfire.PSKSize {
		return fmt.Errorf("invalid campfire PSK size")
	}
	if o.WaitCampfirePSK != "" && len(o.WaitCampfirePSK) != campfire.PSKSize {
		return fmt.Errorf("invalid campfire PSK size")
	}
	return nil
}
