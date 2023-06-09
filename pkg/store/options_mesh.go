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
	"time"

	"github.com/webmeshproj/node/pkg/util"
)

const (
	NodeIDEnvVar                 = "MESH_NODE_ID"
	KeyRotationIntervalEnvVar    = "MESH_KEY_ROTATION_INTERVAL"
	ZoneAwarenessIDEnvVar        = "MESH_ZONE_AWARENESS_ID"
	JoinAddressEnvVar            = "MESH_JOIN_ADDRESS"
	JoinAsVoterEnvVar            = "MESH_JOIN_AS_VOTER"
	MaxJoinRetriesEnvVar         = "MESH_MAX_JOIN_RETRIES"
	JoinTimeoutEnvVar            = "MESH_JOIN_TIMEOUT"
	GRPCAdvertisePortEnvVar      = "MESH_GRPC_PORT"
	PrimaryEndpointEnvVar        = "MESH_PRIMARY_ENDPOINT"
	NodeWireGuardEndpointsEnvVar = "MESH_WIREGUARD_ENDPOINTS"
	NoIPv4EnvVar                 = "MESH_NO_IPV4"
	NoIPv6EnvVar                 = "MESH_NO_IPV6"
)

// MeshOptions are the options for participating in a mesh.
type MeshOptions struct {
	// NodeID is the node ID.
	NodeID string `json:"node-id,omitempty" yaml:"node-id,omitempty" toml:"node-id,omitempty"`
	// KeyRotationInterval is the interval to rotate wireguard keys.
	// Set this to 0 to disable key rotation.
	KeyRotationInterval time.Duration `json:"key-rotation-interval,omitempty" yaml:"key-rotation-interval,omitempty" toml:"key-rotation-interval,omitempty"`
	// ZoneAwarenessID is the zone awareness ID.
	ZoneAwarenessID string `json:"zone-awareness-id,omitempty" yaml:"zone-awareness-id,omitempty" toml:"zone-awareness-id,omitempty"`
	// JoinAddress is the address of a node to join.
	JoinAddress string `json:"join-address,omitempty" yaml:"join-address,omitempty" toml:"join-address,omitempty"`
	// MaxJoinRetries is the maximum number of join retries.
	MaxJoinRetries int `json:"max-join-retries,omitempty" yaml:"max-join-retries,omitempty" toml:"max-join-retries,omitempty"`
	// JoinTimeout is the timeout for joining.
	JoinTimeout time.Duration `json:"join-timeout,omitempty" yaml:"join-timeout,omitempty" toml:"join-timeout,omitempty"`
	// Voter is true if the node should be a voter.
	JoinAsVoter bool `json:"voter,omitempty" yaml:"voter,omitempty" toml:"voter,omitempty"`
	// PrimaryEndpoint is the primary endpoint to advertise when joining.
	PrimaryEndpoint string `json:"primary-endpoint,omitempty" yaml:"primary-endpoint,omitempty" toml:"primary-endpoint,omitempty"`
	// WireGuardEndpoints are additional WireGuard endpoints to broadcast when joining.
	WireGuardEndpoints string `json:"wireguard-endpoints,omitempty" yaml:"wireguard-endpoints,omitempty" toml:"wireguard-endpoints,omitempty"`
	// GRPCPort is the port to advertise for gRPC.
	GRPCPort int `json:"grpc-port,omitempty" yaml:"grpc-port,omitempty" toml:"grpc-port,omitempty"`
	// NoIPv4 disables IPv4 usage.
	NoIPv4 bool `json:"no-ipv4,omitempty" yaml:"no-ipv4,omitempty" toml:"no-ipv4,omitempty"`
	// NoIPv6 disables IPv6 usage.
	NoIPv6 bool `json:"no-ipv6,omitempty" yaml:"no-ipv6,omitempty" toml:"no-ipv6,omitempty"`
}

// NewMeshOptions creates a new MeshOptions with default values.
func NewMeshOptions() *MeshOptions {
	return &MeshOptions{
		JoinAddress:         "",
		MaxJoinRetries:      10,
		GRPCPort:            8443,
		JoinTimeout:         time.Minute,
		KeyRotationInterval: time.Hour * 24 * 7,
	}
}

const hostnameFlagDefault = "<hostname>"

// BindFlags binds the MeshOptions to a flag set.
func (o *MeshOptions) BindFlags(fl *flag.FlagSet) {
	fl.StringVar(&o.NodeID, "mesh.node-id", util.GetEnvDefault(NodeIDEnvVar, hostnameFlagDefault),
		`Store node ID. If not set, the ID comes from the following decision tree.
1. If mTLS is enabled, the node ID is the CN of the client certificate.
2. If mTLS is not enabled, the node ID is the hostname of the machine.
3. If the hostname is not available, the node ID is a random UUID (should only be used for testing).`)

	fl.DurationVar(&o.KeyRotationInterval, "mesh.key-rotation-interval", util.GetEnvDurationDefault(KeyRotationIntervalEnvVar, time.Hour*24*7),
		"Interval to rotate WireGuard keys. Set this to 0 to disable key rotation.")

	fl.StringVar(&o.ZoneAwarenessID, "mesh.zone-awareness-id", util.GetEnvDefault(ZoneAwarenessIDEnvVar, ""),
		"Zone awareness ID. If set, the server will prioritize peer endpoints in the same zone.")

	fl.StringVar(&o.JoinAddress, "mesh.join-address", util.GetEnvDefault(JoinAddressEnvVar, ""),
		"Address of a node to join.")
	fl.IntVar(&o.MaxJoinRetries, "mesh.max-join-retries", util.GetEnvIntDefault(MaxJoinRetriesEnvVar, 10),
		"Maximum number of join retries.")
	fl.DurationVar(&o.JoinTimeout, "mesh.join-timeout", util.GetEnvDurationDefault(JoinTimeoutEnvVar, time.Minute),
		"Join timeout.")
	fl.BoolVar(&o.JoinAsVoter, "mesh.join-as-voter", util.GetEnvDefault(JoinAsVoterEnvVar, "false") == "true",
		"Join the cluster as a voter. Default behavior is to join as an observer.")
	fl.IntVar(&o.GRPCPort, "mesh.grpc-port", util.GetEnvIntDefault(GRPCAdvertisePortEnvVar, 8443),
		"GRPC advertise port.")
	fl.StringVar(&o.PrimaryEndpoint, "mesh.primary-endpoint", util.GetEnvDefault(PrimaryEndpointEnvVar, ""),
		`The primary endpoint to broadcast when joining a cluster.
This is only necessary if the node intends on being publicly accessible.`)
	fl.StringVar(&o.WireGuardEndpoints, "mesh.wireguard-endpoints", util.GetEnvDefault(NodeWireGuardEndpointsEnvVar, ""),
		`Comma separated list of additional WireGuard endpoints to broadcast when joining a cluster.`)
	fl.BoolVar(&o.NoIPv4, "mesh.no-ipv4", util.GetEnvDefault(NoIPv4EnvVar, "false") == "true",
		"Do not request IPv4 assignments when joining.")
	fl.BoolVar(&o.NoIPv6, "mesh.no-ipv6", util.GetEnvDefault(NoIPv6EnvVar, "false") == "true",
		"Do not request IPv6 assignments when joining.")
}

// Validate validates the MeshOptions.
func (o *MeshOptions) Validate() error {
	if o.KeyRotationInterval < 0 {
		return errors.New("key rotation interval must be >= 0")
	}
	return nil
}
