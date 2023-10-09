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
	"github.com/webmeshproj/webmesh/pkg/services/metrics"
	"github.com/webmeshproj/webmesh/pkg/services/turn"
	"github.com/webmeshproj/webmesh/pkg/services/webrtc"
)

func TestServiceOptionsValidate(t *testing.T) {
	t.Parallel()
	defaults := NewServiceOptions(false)
	insecureDefaults := NewInsecureServiceOptions(false)
	tc := []struct {
		name    string
		opts    *ServiceOptions
		wantErr bool
	}{
		{
			name: "NilOptions",
			opts: nil,
			// This is a bit of a weird case, but it's not invalid to have a nil
			// ServiceOptions.
			wantErr: false,
		},
		{
			name: "Defaults",
			opts: &defaults,
			// Defaults are invalid without explicitly setting insecure.
			wantErr: true,
		},
		{
			name:    "InsecureDefaults",
			opts:    &insecureDefaults,
			wantErr: false,
		},
		{
			name: "DisabledAPI",
			opts: &ServiceOptions{
				API: APIOptions{
					Disabled:      true,
					ListenAddress: services.DefaultGRPCListenAddress,
				},
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: false,
		},
		{
			name: "NoListenAddress",
			opts: &ServiceOptions{
				API: APIOptions{
					Disabled:      false,
					ListenAddress: "",
				},
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: true,
		},
		{
			name: "InvalidListenAddress",
			opts: &ServiceOptions{
				API: APIOptions{
					Disabled:      false,
					ListenAddress: "invalid",
				},
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: true,
		},
		{
			name: "ValidInsecureOptions",
			opts: &ServiceOptions{
				API: APIOptions{
					Disabled:      false,
					ListenAddress: services.DefaultGRPCListenAddress,
					Insecure:      true,
				},
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: false,
		},
		{
			name: "NoTLSCertFile",
			opts: &ServiceOptions{
				API: APIOptions{
					Disabled:      false,
					ListenAddress: services.DefaultGRPCListenAddress,
					TLSKeyFile:    "keyfile",
				},
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: true,
		},
		{
			name: "NoTLSKeyFile",
			opts: &ServiceOptions{
				API: APIOptions{
					Disabled:      false,
					ListenAddress: services.DefaultGRPCListenAddress,
					TLSCertFile:   "certfile",
				},
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: true,
		},
		{
			name: "NoTLSCertData",
			opts: &ServiceOptions{
				API: APIOptions{
					Disabled:      false,
					ListenAddress: services.DefaultGRPCListenAddress,
					TLSKeyData:    "keydata",
				},
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: true,
		},
		{
			name: "NoTLSKeyData",
			opts: &ServiceOptions{
				API: APIOptions{
					Disabled:      false,
					ListenAddress: services.DefaultGRPCListenAddress,
					TLSCertData:   "certdata",
				},
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: true,
		},
		{
			name: "TLSFileKeyPair",
			opts: &ServiceOptions{
				API: APIOptions{
					Disabled:      false,
					ListenAddress: services.DefaultGRPCListenAddress,
					TLSCertFile:   "certfile",
					TLSKeyFile:    "keyfile",
				},
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: false,
		},
		{
			name: "TLSDataKeyPair",
			opts: &ServiceOptions{
				API: APIOptions{
					Disabled:      false,
					ListenAddress: services.DefaultGRPCListenAddress,
					TLSCertData:   "certdata",
					TLSKeyData:    "keydata",
				},
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: false,
		},
		{
			name: "DisabledWebRTCAPI",
			opts: &ServiceOptions{
				API: NewInsecureAPIOptions(false),
				WebRTC: WebRTCOptions{
					Enabled: false,
				},
				MeshDNS: NewMeshDNSOptions(),
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: false,
		},
		{
			name: "InvalidSTUNServers",
			opts: &ServiceOptions{
				API: NewInsecureAPIOptions(false),
				WebRTC: WebRTCOptions{
					Enabled: true,
					STUNServers: []string{
						"invalid",
					},
				},
				MeshDNS: NewMeshDNSOptions(),
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: true,
		},
		{
			name: "ValidSTUNServers",
			opts: &ServiceOptions{
				API: NewInsecureAPIOptions(false),
				WebRTC: WebRTCOptions{
					Enabled:     true,
					STUNServers: webrtc.DefaultSTUNServers,
				},
				MeshDNS: NewMeshDNSOptions(),
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: false,
		},
		{
			name: "DisabledTURNServer",
			opts: &ServiceOptions{
				API:     NewInsecureAPIOptions(false),
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN: TURNOptions{
					Enabled: false,
				},
				Metrics: NewMetricsOptions(),
			},
			wantErr: false,
		},
		{
			name: "NoTURNListenAddress",
			opts: &ServiceOptions{
				API:     NewInsecureAPIOptions(false),
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN: TURNOptions{
					Enabled:       true,
					Endpoint:      "127.0.0.1",
					PublicIP:      "127.0.0.1",
					ListenAddress: "",
					Realm:         "webmesh",
					TURNPortRange: turn.DefaultPortRange,
				},
				Metrics: NewMetricsOptions(),
			},
			wantErr: true,
		},
		{
			name: "InvalidTURNListenAddress",
			opts: &ServiceOptions{
				API:     NewInsecureAPIOptions(false),
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN: TURNOptions{
					Enabled:       true,
					Endpoint:      "127.0.0.1",
					PublicIP:      "127.0.0.1",
					ListenAddress: "invalid",
					Realm:         "webmesh",
					TURNPortRange: turn.DefaultPortRange,
				},
				Metrics: NewMetricsOptions(),
			},
			wantErr: true,
		},
		{
			name: "ValidTURNListenAddress",
			opts: &ServiceOptions{
				API:     NewInsecureAPIOptions(false),
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN: TURNOptions{
					Enabled:       true,
					Endpoint:      "127.0.0.1",
					PublicIP:      "127.0.0.1",
					ListenAddress: turn.DefaultListenAddress,
					Realm:         "webmesh",
					TURNPortRange: turn.DefaultPortRange,
				},
				Metrics: NewMetricsOptions(),
			},
			wantErr: false,
		},
		{
			name: "NoTURNPublicIPOrEndpoint",
			opts: &ServiceOptions{
				API:     NewInsecureAPIOptions(false),
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN: TURNOptions{
					Enabled:       true,
					Endpoint:      "",
					PublicIP:      "",
					ListenAddress: turn.DefaultListenAddress,
					Realm:         "webmesh",
					TURNPortRange: turn.DefaultPortRange,
				},
				Metrics: NewMetricsOptions(),
			},
			wantErr: true,
		},
		{
			name: "InvalidTURNPublicIP",
			opts: &ServiceOptions{
				API:     NewInsecureAPIOptions(false),
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN: TURNOptions{
					Enabled:       true,
					PublicIP:      "invalid",
					ListenAddress: turn.DefaultListenAddress,
					Realm:         "webmesh",
					TURNPortRange: turn.DefaultPortRange,
				},
				Metrics: NewMetricsOptions(),
			},
			wantErr: true,
		},
		{
			name: "InvalidTURNPortRange",
			opts: &ServiceOptions{
				API:     NewInsecureAPIOptions(false),
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN: TURNOptions{
					Enabled:       true,
					PublicIP:      "127.0.0.1",
					ListenAddress: turn.DefaultListenAddress,
					Realm:         "webmesh",
					TURNPortRange: "invalid",
				},
				Metrics: NewMetricsOptions(),
			},
			wantErr: true,
		},
		{
			name: "DisabledDNSOptions",
			opts: &ServiceOptions{
				API:    NewInsecureAPIOptions(false),
				WebRTC: NewWebRTCOptions(),
				MeshDNS: MeshDNSOptions{
					Enabled: false,
				},
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: false,
		},
		{
			name: "NoDNSListenAddrs",
			opts: &ServiceOptions{
				API:    NewInsecureAPIOptions(false),
				WebRTC: NewWebRTCOptions(),
				MeshDNS: MeshDNSOptions{
					Enabled: true,
				},
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: true,
		},
		{
			name: "InvalidDNSTCPAddr",
			opts: &ServiceOptions{
				API:    NewInsecureAPIOptions(false),
				WebRTC: NewWebRTCOptions(),
				MeshDNS: MeshDNSOptions{
					Enabled:   true,
					ListenTCP: "invalid",
				},
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: true,
		},
		{
			name: "InvalidDNSUDPAddr",
			opts: &ServiceOptions{
				API:    NewInsecureAPIOptions(false),
				WebRTC: NewWebRTCOptions(),
				MeshDNS: MeshDNSOptions{
					Enabled:   true,
					ListenUDP: "invalid",
				},
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: true,
		},
		{
			name: "ValidDNSUDPAddr",
			opts: &ServiceOptions{
				API:    NewInsecureAPIOptions(false),
				WebRTC: NewWebRTCOptions(),
				MeshDNS: MeshDNSOptions{
					Enabled:   true,
					ListenUDP: meshdns.DefaultListenUDP,
				},
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: false,
		},
		{
			name: "ValidDNSTCPAddr",
			opts: &ServiceOptions{
				API:    NewInsecureAPIOptions(false),
				WebRTC: NewWebRTCOptions(),
				MeshDNS: MeshDNSOptions{
					Enabled:   true,
					ListenTCP: meshdns.DefaultListenTCP,
				},
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: false,
		},
		{
			name: "ValidDNSTCPAndUDPAddr",
			opts: &ServiceOptions{
				API:    NewInsecureAPIOptions(false),
				WebRTC: NewWebRTCOptions(),
				MeshDNS: MeshDNSOptions{
					Enabled:   true,
					ListenTCP: meshdns.DefaultListenTCP,
					ListenUDP: meshdns.DefaultListenUDP,
				},
				TURN:    NewTURNOptions(),
				Metrics: NewMetricsOptions(),
			},
			wantErr: false,
		},
		{
			name: "DisabledMetrics",
			opts: &ServiceOptions{
				API:     NewInsecureAPIOptions(false),
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN:    NewTURNOptions(),
				Metrics: MetricsOptions{
					Enabled: false,
				},
			},
			wantErr: false,
		},
		{
			name: "NoMetricsAddress",
			opts: &ServiceOptions{
				API:     NewInsecureAPIOptions(false),
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN:    NewTURNOptions(),
				Metrics: MetricsOptions{
					Enabled:       true,
					ListenAddress: "",
				},
			},
			wantErr: true,
		},
		{
			name: "InvalidMetricsAddress",
			opts: &ServiceOptions{
				API:     NewInsecureAPIOptions(false),
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN:    NewTURNOptions(),
				Metrics: MetricsOptions{
					Enabled:       true,
					ListenAddress: "invalid",
				},
			},
			wantErr: true,
		},
		{
			name: "ValidMetricsAddress",
			opts: &ServiceOptions{
				API:     NewInsecureAPIOptions(false),
				WebRTC:  NewWebRTCOptions(),
				MeshDNS: NewMeshDNSOptions(),
				TURN:    NewTURNOptions(),
				Metrics: MetricsOptions{
					Enabled:       true,
					ListenAddress: metrics.DefaultListenAddress,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			if tt.opts != nil {
				// Make sure we can bind to flags without panicking.
				tt.opts.BindFlags("", pflag.NewFlagSet(tt.name, pflag.PanicOnError))
			}
			if err := tt.opts.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("ServiceOptions.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
