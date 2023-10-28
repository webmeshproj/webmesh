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
	"testing"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/services/meshdns"
)

func TestMeshConfigValidation(t *testing.T) {
	t.Parallel()
	defaults := NewMeshOptions("node-id")
	defaultsNoID := NewMeshOptions("")
	defaultsInvalidID := NewMeshOptions("invalid/node/id")
	tc := []struct {
		name    string
		cfg     *MeshOptions
		wantErr bool
	}{
		{
			name:    "NilValues",
			cfg:     nil,
			wantErr: true,
		},
		{
			name:    "DefaultValues",
			cfg:     &defaults,
			wantErr: false,
		},
		{
			name:    "NoNodeID",
			cfg:     &defaultsNoID,
			wantErr: false, // We attempt to generate one
		},
		{
			name:    "InvalidNodeID",
			cfg:     &defaultsInvalidID,
			wantErr: true,
		},
		{
			name: "InvalidIPPreferences",
			cfg: &MeshOptions{
				NodeID:               "test-node",
				GRPCAdvertisePort:    services.DefaultGRPCPort,
				MeshDNSAdvertisePort: meshdns.DefaultAdvertisePort,
				DisableIPv4:          true,
				DisableIPv6:          true,
			},
			wantErr: true,
		},
		{
			name: "InvalidStorageIPPreferences",
			cfg: &MeshOptions{
				NodeID:               "test-node",
				GRPCAdvertisePort:    services.DefaultGRPCPort,
				MeshDNSAdvertisePort: meshdns.DefaultAdvertisePort,
				DisableIPv4:          false,
				DisableIPv6:          true,
				StoragePreferIPv6:    true,
			},
			wantErr: true,
		},
		{
			name: "InvalidJoinAddress",
			cfg: &MeshOptions{
				NodeID:               "test-node",
				JoinAddresses:        []string{"invalid"},
				MaxJoinRetries:       10,
				GRPCAdvertisePort:    services.DefaultGRPCPort,
				MeshDNSAdvertisePort: meshdns.DefaultAdvertisePort,
			},
			wantErr: true,
		},
		{
			name: "ValidJoinAddress",
			cfg: &MeshOptions{
				NodeID:               "test-node",
				JoinAddresses:        []string{"localhost:8080"},
				MaxJoinRetries:       10,
				GRPCAdvertisePort:    services.DefaultGRPCPort,
				MeshDNSAdvertisePort: meshdns.DefaultAdvertisePort,
			},
			wantErr: false,
		},
		{
			name: "InvalidRetryCount",
			cfg: &MeshOptions{
				NodeID:               "test-node",
				JoinAddresses:        []string{"localhost:8080"},
				MaxJoinRetries:       0,
				GRPCAdvertisePort:    services.DefaultGRPCPort,
				MeshDNSAdvertisePort: meshdns.DefaultAdvertisePort,
			},
			wantErr: true,
		},
		{
			name: "InvalidSuffrage",
			cfg: &MeshOptions{
				NodeID:               "test-node",
				GRPCAdvertisePort:    services.DefaultGRPCPort,
				MeshDNSAdvertisePort: meshdns.DefaultAdvertisePort,
				RequestVote:          true,
				RequestObserver:      true,
			},
			wantErr: true,
		},
		{
			name: "InvalidPrimaryEndpoint",
			cfg: &MeshOptions{
				NodeID:               "test-node",
				GRPCAdvertisePort:    services.DefaultGRPCPort,
				MeshDNSAdvertisePort: meshdns.DefaultAdvertisePort,
				PrimaryEndpoint:      "invalid:host",
			},
			wantErr: true,
		},
		{
			name: "IPv4PrimaryEndpoint",
			cfg: &MeshOptions{
				NodeID:               "test-node",
				GRPCAdvertisePort:    services.DefaultGRPCPort,
				MeshDNSAdvertisePort: meshdns.DefaultAdvertisePort,
				PrimaryEndpoint:      "127.0.0.1",
			},
			wantErr: false,
		},
		{
			name: "IPv6PrimaryEndpoint",
			cfg: &MeshOptions{
				NodeID:               "test-node",
				GRPCAdvertisePort:    services.DefaultGRPCPort,
				MeshDNSAdvertisePort: meshdns.DefaultAdvertisePort,
				PrimaryEndpoint:      "::1",
			},
			wantErr: false,
		},
		{
			name: "HostnamePrimaryEndpoint",
			cfg: &MeshOptions{
				NodeID:               "test-node",
				GRPCAdvertisePort:    services.DefaultGRPCPort,
				MeshDNSAdvertisePort: meshdns.DefaultAdvertisePort,
				PrimaryEndpoint:      "example.com",
			},
			wantErr: false,
		},
		{
			name: "InvalidICEPeers",
			cfg: &MeshOptions{
				NodeID:               "test-node",
				GRPCAdvertisePort:    services.DefaultGRPCPort,
				MeshDNSAdvertisePort: meshdns.DefaultAdvertisePort,
				ICEPeers:             []string{"/invalid/node/id"},
			},
			wantErr: true,
		},
		{
			name: "ValidICEPeers",
			cfg: &MeshOptions{
				NodeID:               "test-node",
				GRPCAdvertisePort:    services.DefaultGRPCPort,
				MeshDNSAdvertisePort: meshdns.DefaultAdvertisePort,
				ICEPeers:             []string{"another-node"},
			},
			wantErr: false,
		},
		{
			name: "InvalidLibP2PPeers",
			cfg: &MeshOptions{
				NodeID:               "test-node",
				GRPCAdvertisePort:    services.DefaultGRPCPort,
				MeshDNSAdvertisePort: meshdns.DefaultAdvertisePort,
				LibP2PPeers:          []string{"/invalid/node/id"},
			},
			wantErr: true,
		},
		{
			name: "ValidLibP2PPeers",
			cfg: &MeshOptions{
				NodeID:               "test-node",
				GRPCAdvertisePort:    services.DefaultGRPCPort,
				MeshDNSAdvertisePort: meshdns.DefaultAdvertisePort,
				LibP2PPeers:          []string{"another-node"},
			},
			wantErr: false,
		},
		{
			name: "InvalidGRPCPort",
			cfg: &MeshOptions{
				NodeID:               "test-node",
				GRPCAdvertisePort:    -1,
				MeshDNSAdvertisePort: meshdns.DefaultAdvertisePort,
			},
			wantErr: true,
		},
		{
			name: "InvalidDNSPort",
			cfg: &MeshOptions{
				NodeID:               "test-node",
				GRPCAdvertisePort:    services.DefaultGRPCPort,
				MeshDNSAdvertisePort: -1,
			},
			wantErr: true,
		},
		{
			name: "InvalidIPAMNodeIDs",
			cfg: &MeshOptions{
				NodeID:                      "test-node",
				DisableFeatureAdvertisement: true,
				DefaultIPAMStaticIPv4: map[string]string{
					"invalid/node/id": "172.16.0.1/32",
				},
			},
			wantErr: true,
		},
		{
			name: "InvalidIPAMPrefixes",
			cfg: &MeshOptions{
				NodeID:                      "test-node",
				DisableFeatureAdvertisement: true,
				DefaultIPAMStaticIPv4: map[string]string{
					"test-node": "invalid",
				},
			},
			wantErr: true,
		},
		{
			name: "ValidIPAMPrefixes",
			cfg: &MeshOptions{
				NodeID:                      "test-node",
				DisableFeatureAdvertisement: true,
				DefaultIPAMStaticIPv4: map[string]string{
					"test-node": "172.16.0.1/32",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			if tt.cfg != nil {
				// Make sure it binds to flags without panicking
				fs := pflag.NewFlagSet("test", pflag.PanicOnError)
				tt.cfg.BindFlags("test", fs)
			}
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("MeshOptions.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
