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
)

func TestGlobalOptionsValidate(t *testing.T) {
	t.Parallel()
	defaults := NewGlobalOptions()
	tc := []struct {
		name    string
		opts    *GlobalOptions
		wantErr bool
	}{
		{
			name:    "NilOptions",
			opts:    nil,
			wantErr: false,
		},
		{
			name:    "Defaults",
			opts:    &defaults,
			wantErr: false,
		},
		{
			name: "InvalidIPPreferences",
			opts: &GlobalOptions{
				DisableIPv4: true,
				DisableIPv6: true,
			},
			wantErr: true,
		},
		{
			name: "InvalidPrimaryEndpoint",
			opts: &GlobalOptions{
				PrimaryEndpoint: "invalid",
			},
			wantErr: true,
		},
		{
			name: "MTLSNoCertFile",
			opts: &GlobalOptions{
				MTLS:        true,
				TLSCertFile: "",
				TLSKeyFile:  "keyfile",
				TLSCAFile:   "cafile",
			},
			wantErr: true,
		},
		{
			name: "MTLSNoKeyFile",
			opts: &GlobalOptions{
				MTLS:        true,
				TLSCertFile: "certfile",
				TLSKeyFile:  "",
				TLSCAFile:   "cafile",
			},
			wantErr: true,
		},
		{
			name: "MTLSNoCAFile",
			opts: &GlobalOptions{
				MTLS:        true,
				TLSCertFile: "certfile",
				TLSKeyFile:  "keyfile",
				TLSCAFile:   "",
			},
			wantErr: true,
		},
		{
			name: "MTLSValidCAFile",
			opts: &GlobalOptions{
				MTLS:        true,
				TLSCertFile: "certfile",
				TLSKeyFile:  "keyfile",
				TLSCAFile:   "cafile",
			},
			wantErr: false,
		},
		{
			name: "MTLSValidClientCAFile",
			opts: &GlobalOptions{
				MTLS:            true,
				TLSCertFile:     "certfile",
				TLSKeyFile:      "keyfile",
				TLSClientCAFile: "cafile",
			},
			wantErr: false,
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			if tt.opts != nil {
				// Make sure they bind to a flagset without error
				fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
				tt.opts.BindFlags("global.", fs)
			}
			if err := tt.opts.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("GlobalOptions.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestApplyGlobalOptions(t *testing.T) {
	t.Parallel()

	t.Run("ProtocolPreferences", func(t *testing.T) {
		t.Parallel()
		opts := NewDefaultConfig("test")
		opts.Global.DisableIPv4 = true
		opts, err := opts.Global.ApplyGlobals(opts)
		if err != nil {
			t.Errorf("ApplyGlobals() error = %v", err)
		}
		if opts.Mesh.DisableIPv4 != true {
			t.Errorf("ApplyGlobals() expected DisableIPv4 to be true")
		}
		opts.Global.DisableIPv4 = false
		opts.Global.DisableIPv6 = true
		opts, err = opts.Global.ApplyGlobals(opts)
		if err != nil {
			t.Errorf("ApplyGlobals() error = %v", err)
		}
		if opts.Mesh.DisableIPv6 != true {
			t.Errorf("ApplyGlobals() expected DisableIPv6 to be true")
		}
	})

	t.Run("PrimaryEndpoints", func(t *testing.T) {
		t.Parallel()
		t.Run("InvalidPrimaryEndpoint", func(t *testing.T) {
			t.Parallel()
			opts := NewDefaultConfig("test")
			opts.Global.PrimaryEndpoint = "invalid"
			_, err := opts.Global.ApplyGlobals(opts)
			if err == nil {
				t.Errorf("ApplyGlobals() expected error")
			}
		})
		t.Run("ValidPrimaryEndpoint", func(t *testing.T) {
			t.Parallel()
			opts := NewDefaultConfig("test")
			opts.Bootstrap.Enabled = true
			opts.Bootstrap.Transport.TCPListenAddress = "[::]:9090"
			opts.Global.PrimaryEndpoint = "127.0.0.1"
			opts.WireGuard.ListenPort = 1234
			opts.Services.TURN.Enabled = true
			opts.Services.TURN.ListenAddress = "[::]:3478"
			opts, err := opts.Global.ApplyGlobals(opts)
			if err != nil {
				t.Errorf("ApplyGlobals() error = %v", err)
			}
			if opts.Mesh.PrimaryEndpoint != "127.0.0.1" {
				t.Errorf("ApplyGlobals() expected Mesh.PrimaryEndpoint to be 127.0.0.1, got: %s", opts.Mesh.PrimaryEndpoint)
			}
			if opts.Bootstrap.Transport.TCPAdvertiseAddress != "127.0.0.1:9090" {
				t.Errorf("ApplyGlobals() expected Bootstrap.Transport.TCPAdvertiseAddress to be 127.0.0.1:9090, got: %s", opts.Bootstrap.Transport.TCPAdvertiseAddress)
			}
			if len(opts.WireGuard.Endpoints) != 1 {
				t.Fatal("ApplyGlobals() expected exactly one WireGuard endpoint")
			}
			if opts.WireGuard.Endpoints[0] != "127.0.0.1:1234" {
				t.Errorf("ApplyGlobals() expected WireGuard endpoint to be 127.0.0.1:1234 got: %s", opts.WireGuard.Endpoints[0])
			}
			if opts.Services.TURN.Endpoint != "stun:127.0.0.1:3478" {
				t.Errorf("ApplyGlobals() expected TURN endpoint to be stun:127.0.0.1:3478 got: %s", opts.Services.TURN.Endpoint)
			}
			if opts.Services.TURN.PublicIP != "127.0.0.1" {
				t.Errorf("ApplyGlobals() expected TURN public IP to be 127.0.0.1 got: %s", opts.Services.TURN.PublicIP)
			}
		})
	})

	t.Run("LogPreferences", func(t *testing.T) {
		t.Parallel()
		opts := NewDefaultConfig("test")
		opts.Global.LogLevel = "test"
		opts.Global.LogFormat = "test"
		opts, err := opts.Global.ApplyGlobals(opts)
		if err != nil {
			t.Errorf("ApplyGlobals() error = %v", err)
		}
		if opts.Storage.LogLevel != "test" {
			t.Errorf("ApplyGlobals() expected Storage.LogLevel to be test, got: %s", opts.Storage.LogLevel)
		}
		if opts.Storage.LogFormat != "test" {
			t.Errorf("ApplyGlobals() expected Storage.LogFormat to be test, got: %s", opts.Storage.LogFormat)
		}
	})

	t.Run("MTLSOptions", func(t *testing.T) {
		t.Parallel()

		t.Run("WithCAFile", func(t *testing.T) {
			t.Parallel()
			opts := NewDefaultConfig("test")
			opts.Global.MTLS = true
			opts.Global.TLSCertFile = "certfile"
			opts.Global.TLSKeyFile = "keyfile"
			opts.Global.TLSCAFile = "cafile"
			opts, err := opts.Global.ApplyGlobals(opts)
			if err != nil {
				t.Errorf("ApplyGlobals() error = %v", err)
			}
			if opts.Auth.MTLS.CertFile != "certfile" {
				t.Errorf("ApplyGlobals() expected Auth.MTLS.TLSCertFile to be certfile, got: %s", opts.Auth.MTLS.CertFile)
			}
			if opts.Auth.MTLS.KeyFile != "keyfile" {
				t.Errorf("ApplyGlobals() expected Auth.MTLS.TLSKeyFile to be keyfile, got: %s", opts.Auth.MTLS.KeyFile)
			}
			mtlsPlug, ok := opts.Plugins.Configs["mtls"]
			if !ok {
				t.Fatal("ApplyGlobals() expected mtls plugin to be configured")
			}
			caFile, ok := mtlsPlug.Config["ca-file"]
			if !ok {
				t.Fatal("ApplyGlobals() expected mtls plugin to be configured with a ca-file")
			}
			if caFile != "cafile" {
				t.Errorf("ApplyGlobals() expected mtls plugin ca-file to be cafile, got: %s", caFile)
			}
		})

		t.Run("WithClientCAFile", func(t *testing.T) {
			t.Parallel()
			opts := NewDefaultConfig("test")
			opts.Global.MTLS = true
			opts.Global.TLSCertFile = "certfile"
			opts.Global.TLSKeyFile = "keyfile"
			opts.Global.TLSClientCAFile = "clientcafile"
			opts, err := opts.Global.ApplyGlobals(opts)
			if err != nil {
				t.Errorf("ApplyGlobals() error = %v", err)
			}
			if opts.Auth.MTLS.CertFile != "certfile" {
				t.Errorf("ApplyGlobals() expected Auth.MTLS.TLSCertFile to be certfile, got: %s", opts.Auth.MTLS.CertFile)
			}
			if opts.Auth.MTLS.KeyFile != "keyfile" {
				t.Errorf("ApplyGlobals() expected Auth.MTLS.TLSKeyFile to be keyfile, got: %s", opts.Auth.MTLS.KeyFile)
			}
			mtlsPlug, ok := opts.Plugins.Configs["mtls"]
			if !ok {
				t.Fatal("ApplyGlobals() expected mtls plugin to be configured")
			}
			caFile, ok := mtlsPlug.Config["ca-file"]
			if !ok {
				t.Fatal("ApplyGlobals() expected mtls plugin to be configured with a ca-file")
			}
			if caFile != "clientcafile" {
				t.Errorf("ApplyGlobals() expected mtls plugin ca-file to be cafile, got: %s", caFile)
			}
		})
	})

	t.Run("TLSOptions", func(t *testing.T) {
		t.Parallel()

		t.Run("Insecure", func(t *testing.T) {
			t.Parallel()
			opts := NewDefaultConfig("test")
			opts.Global.Insecure = true
			opts, err := opts.Global.ApplyGlobals(opts)
			if err != nil {
				t.Errorf("ApplyGlobals() error = %v", err)
			}
			if opts.TLS.Insecure != true {
				t.Errorf("ApplyGlobals() expected TLS.Insecure to be true, got: %v", opts.TLS.Insecure)
			}
			if opts.Services.API.Insecure != true {
				t.Errorf("ApplyGlobals() expected Services.API.Insecure to be true, got: %v", opts.Services.API.Insecure)
			}
		})

		t.Run("SkipVerify", func(t *testing.T) {
			t.Parallel()
			opts := NewDefaultConfig("test")
			opts.Global.InsecureSkipVerify = true
			opts, err := opts.Global.ApplyGlobals(opts)
			if err != nil {
				t.Errorf("ApplyGlobals() error = %v", err)
			}
			if opts.TLS.InsecureSkipVerify != true {
				t.Errorf("ApplyGlobals() expected TLS.InsecureSkipVerify to be true, got: %v", opts.TLS.InsecureSkipVerify)
			}
		})

		t.Run("VerifyChainOnly", func(t *testing.T) {
			t.Parallel()
			opts := NewDefaultConfig("test")
			opts.Global.VerifyChainOnly = true
			opts, err := opts.Global.ApplyGlobals(opts)
			if err != nil {
				t.Errorf("ApplyGlobals() error = %v", err)
			}
			if opts.TLS.VerifyChainOnly != true {
				t.Errorf("ApplyGlobals() expected TLS.VerifyChainOnly to be true, got: %v", opts.TLS.VerifyChainOnly)
			}
		})

		t.Run("KeyPair", func(t *testing.T) {
			t.Parallel()
			opts := NewDefaultConfig("test")
			opts.Global.TLSCertFile = "certfile"
			opts.Global.TLSKeyFile = "keyfile"
			opts, err := opts.Global.ApplyGlobals(opts)
			if err != nil {
				t.Errorf("ApplyGlobals() error = %v", err)
			}
			if opts.Services.API.TLSCertFile != "certfile" {
				t.Errorf("ApplyGlobals() expected Services.API.TLSCertFile to be certfile, got: %s", opts.Services.API.TLSCertFile)
			}
			if opts.Services.API.TLSKeyFile != "keyfile" {
				t.Errorf("ApplyGlobals() expected Services.API.TLSKeyFile to be keyfile, got: %s", opts.Services.API.TLSKeyFile)
			}
		})
	})
}
