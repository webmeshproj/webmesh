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
	"time"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system/firewall"
)

func TestValidateBootstrapOptions(t *testing.T) {
	t.Parallel()
	defaults := NewBootstrapOptions()
	tc := []struct {
		name    string
		opts    *BootstrapOptions
		wantErr bool
	}{
		{
			name:    "NilOptions",
			wantErr: false,
		},
		{
			name:    "DefaultOptions",
			opts:    &defaults,
			wantErr: false,
		},
		{
			name: "DisabledOptions",
			opts: &BootstrapOptions{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "NoIPv4Network",
			opts: &BootstrapOptions{
				Enabled:              true,
				MeshDomain:           "cluster.local",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport:            NewBootstrapTransportOptions(),
			},
			wantErr: true,
		},
		{
			name: "InvalidIPv4Network",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "invalid",
				MeshDomain:           "cluster.local",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport:            NewBootstrapTransportOptions(),
			},
			wantErr: true,
		},
		{
			name: "IPv6NetworkForIPv4Network",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "2001:db8::/32",
				MeshDomain:           "cluster.local",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport:            NewBootstrapTransportOptions(),
			},
			wantErr: true,
		},
		{
			name: "ValidIPv4Network",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "cluster.local",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport:            NewBootstrapTransportOptions(),
			},
			wantErr: false,
		},
		{
			name: "NoMeshDomain",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport:            NewBootstrapTransportOptions(),
			},
			wantErr: true,
		},
		{
			name: "ValidMeshDomain",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "webmesh.internal",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport:            NewBootstrapTransportOptions(),
			},
			wantErr: false,
		},
		{
			name: "NoAdmin",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "webmesh.internal",
				Admin:                "",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport:            NewBootstrapTransportOptions(),
			},
			wantErr: true,
		},
		{
			name: "InvalidAdmin",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "webmesh.internal",
				Admin:                "invalid/node/id",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport:            NewBootstrapTransportOptions(),
			},
			wantErr: true,
		},
		{
			name: "ValidAdmin",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "webmesh.internal",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport:            NewBootstrapTransportOptions(),
			},
			wantErr: false,
		},
		{
			name: "NoNetworkPolicy",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "webmesh.internal",
				Admin:                "admin",
				DefaultNetworkPolicy: "",
				Transport:            NewBootstrapTransportOptions(),
			},
			wantErr: true,
		},
		{
			name: "InvalidNetworkPolicy",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "webmesh.internal",
				Admin:                "admin",
				DefaultNetworkPolicy: "invalid",
				Transport:            NewBootstrapTransportOptions(),
			},
			wantErr: true,
		},
		{
			name: "ValidAcceptNetworkPolicy",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "webmesh.internal",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport:            NewBootstrapTransportOptions(),
			},
			wantErr: false,
		},
		{
			name: "ValidDropNetworkPolicy",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "webmesh.internal",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyDrop),
				Transport:            NewBootstrapTransportOptions(),
			},
			wantErr: false,
		},
		{
			name: "NoTCPAdvertiseAddress",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "webmesh.internal",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport: BootstrapTransportOptions{
					TCPAdvertiseAddress: "",
					TCPListenAddress:    "[::]:8080",
				},
			},
			wantErr: true,
		},
		{
			name: "InvalidTCPAdvertiseAddress",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "webmesh.internal",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport: BootstrapTransportOptions{
					TCPAdvertiseAddress: "invaid",
					TCPListenAddress:    "[::]:8080",
				},
			},
			wantErr: true,
		},
		{
			name: "NoTCPListenAddress",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "webmesh.internal",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport: BootstrapTransportOptions{
					TCPAdvertiseAddress: "127.0.0.1:8080",
					TCPListenAddress:    "",
				},
			},
			wantErr: true,
		},
		{
			name: "InvalidTCPListenAddress",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "webmesh.internal",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport: BootstrapTransportOptions{
					TCPAdvertiseAddress: "127.0.0.1:8080",
					TCPListenAddress:    "invalid",
				},
			},
			wantErr: true,
		},
		{
			name: "ValidTCPTransportOptions",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "webmesh.internal",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport: BootstrapTransportOptions{
					TCPAdvertiseAddress: "127.0.0.1:8080",
					TCPListenAddress:    "[::]:8080",
				},
			},
			wantErr: false,
		},
		{
			name: "NoRendezvousNodes",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "webmesh.internal",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport: BootstrapTransportOptions{
					Rendezvous:       "test",
					RendezvousNodes:  []string{},
					RendezvousLinger: time.Second,
					PSK:              crypto.MustGeneratePSK().String(),
				},
			},
			wantErr: true,
		},
		{
			name: "NoPSK",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "webmesh.internal",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport: BootstrapTransportOptions{
					Rendezvous:       "test",
					RendezvousNodes:  []string{"test"},
					RendezvousLinger: time.Second,
				},
			},
			wantErr: true,
		},
		{
			name: "InvalidPSK",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "webmesh.internal",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport: BootstrapTransportOptions{
					Rendezvous:       "test",
					RendezvousNodes:  []string{"test"},
					RendezvousLinger: time.Second,
					PSK:              "invalid",
				},
			},
			wantErr: true,
		},
		{
			name: "NoRendezvous",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "webmesh.internal",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport: BootstrapTransportOptions{
					Rendezvous:       "",
					RendezvousNodes:  []string{"test"},
					RendezvousLinger: time.Second,
					PSK:              crypto.MustGeneratePSK().String(),
				},
			},
			wantErr: true,
		},
		{
			name: "NoRendezvousLinger",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "webmesh.internal",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport: BootstrapTransportOptions{
					Rendezvous:       "test",
					RendezvousNodes:  []string{"test"},
					RendezvousLinger: 0,
					PSK:              crypto.MustGeneratePSK().String(),
				},
			},
			wantErr: true,
		},
		{
			name: "ValidRendezvousOptions",
			opts: &BootstrapOptions{
				Enabled:              true,
				IPv4Network:          "172.16.0.0/12",
				MeshDomain:           "webmesh.internal",
				Admin:                "admin",
				DefaultNetworkPolicy: string(firewall.PolicyAccept),
				Transport: BootstrapTransportOptions{
					Rendezvous:       "test",
					RendezvousNodes:  []string{"test"},
					RendezvousLinger: time.Second,
					PSK:              crypto.MustGeneratePSK().String(),
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			if tt.opts != nil {
				// Make sure we can bind them to a flag set
				fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
				tt.opts.BindFlags("test", fs)
			}
			err := tt.opts.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Expected no error but got %v", err)
			}
		})
	}
}
