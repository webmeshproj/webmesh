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
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/net/endpoints"
)

// GlobalOptions are options that will be re-applied to all relevant configurations after parsing.
type GlobalOptions struct {
	// LogLevel is the log level.
	LogLevel string `koanf:"log-level,omitempty"`
	// TLSCertFile is the TLS certificate file.
	TLSCertFile string `koanf:"tls-cert-file,omitempty"`
	// TLSKeyFile is the TLS key file.
	TLSKeyFile string `koanf:"tls-key-file,omitempty"`
	// TLACAFile is the TLS CA file.
	TLSCAFile string `koanf:"tls-ca-file,omitempty"`
	// TLSClientCAFile is the path to the TLS client CA file.
	// If empty, either TLSCAFile or the system CA pool is used.
	TLSClientCAFile string `koanf:"tls-client-ca-file,omitempty"`
	// MTLS is true if mutual TLS is enabled.
	MTLS bool `koanf:"mtls,omitempty"`
	// VerifyChainOnly is true if only the chain should be verified.
	VerifyChainOnly bool `koanf:"verify-chain-only,omitempty"`
	// InsecureSkipVerify is true if the server TLS cert should not be verified.
	InsecureSkipVerify bool `koanf:"insecure-skip-verify,omitempty"`
	// Insecure is true if TLS should be disabled.
	Insecure bool `koanf:"insecure,omitempty"`
	// PrimaryEndpoint is the preferred publicly routable address of this node.
	// Setting this value will override the mesh advertise address with its
	// configured listen port.
	PrimaryEndpoint string `koanf:"primary-endpoint,omitempty"`
	// Endpoints are the additional publicly routable addresses of this node.
	// If PrimaryEndpoint is not set, it will be set to the first endpoint.
	// Setting this value will override the mesh advertise with its configured
	// listen port.
	Endpoints []string `koanf:"endpoints,omitempty"`
	// DetectEndpoints is true if the endpoints should be detected.
	DetectEndpoints bool `koanf:"detect-endpoints,omitempty"`
	// DetectPrivateEndpoints is true if private IP addresses should be included in detection.
	// This automatically enables DetectEndpoints.
	DetectPrivateEndpoints bool `koanf:"detect-private-endpoints,omitempty"`
	// AllowRemoteDetection is true if remote detection is allowed.
	AllowRemoteDetection bool `koanf:"allow-remote-detection,omitempty"`
	// DetectIPv6 is true if IPv6 addresses should be included in detection.
	DetectIPv6 bool `koanf:"detect-ipv6,omitempty"`
	// DisableIPv4 is true if IPv4 should be disabled.
	DisableIPv4 bool `koanf:"disable-ipv4,omitempty"`
	// DisableIPv6 is true if IPv6 should be disabled.
	DisableIPv6 bool `koanf:"disable-ipv6,omitempty"`
}

func (o *GlobalOptions) BindFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.LogLevel, "global.log-level", "info", "Log level.")
	fs.StringVar(&o.TLSCertFile, "global.tls-cert-file", "", "TLS certificate file.")
	fs.StringVar(&o.TLSKeyFile, "global.tls-key-file", "", "TLS key file.")
	fs.StringVar(&o.TLSCAFile, "global.tls-ca-file", "", "TLS CA file.")
	fs.StringVar(&o.TLSClientCAFile, "global.tls-client-ca-file", "", "TLS client CA file.")
	fs.BoolVar(&o.MTLS, "global.mtls", false, "Enable mutual TLS.")
	fs.BoolVar(&o.VerifyChainOnly, "global.verify-chain-only", false, "Verify only the certificate chain.")
	fs.BoolVar(&o.Insecure, "global.insecure", false, "Disable TLS.")
	fs.BoolVar(&o.InsecureSkipVerify, "global.insecure-skip-verify", false, "Skip TLS verification.")
	fs.StringVar(&o.PrimaryEndpoint, "global.primary-endpoint", "", "Primary endpoint to advertise when joining.")
	fs.StringSliceVar(&o.Endpoints, "global.endpoints", nil, "Additional endpoints to advertise when joining.")
	fs.BoolVar(&o.DetectEndpoints, "global.detect-endpoints", false, "Detect and advertise publicly routable endpoints.")
	fs.BoolVar(&o.DetectPrivateEndpoints, "global.detect-private-endpoints", false, "Detect and advertise private endpoints.")
	fs.BoolVar(&o.AllowRemoteDetection, "global.allow-remote-detection", false, "Allow remote endpoint detection.")
	fs.BoolVar(&o.DetectIPv6, "global.detect-ipv6", false, "Detect and advertise IPv6 endpoints.")
	fs.BoolVar(&o.DisableIPv4, "global.disable-ipv4", false, "Disable IPv4.")
	fs.BoolVar(&o.DisableIPv6, "global.disable-ipv6", false, "Disable IPv6.")
}

// Validate validates the global options.
func (o *GlobalOptions) Validate() error {
	if o.DisableIPv4 && o.DisableIPv6 {
		return fmt.Errorf("both IPv4 and IPv6 are disabled")
	}
	if o.MTLS && o.TLSCertFile == "" {
		return fmt.Errorf("mtls is enabled but no tls-cert-file is set")
	}
	if o.MTLS && o.TLSKeyFile == "" {
		return fmt.Errorf("mtls is enabled but no tls-key-file is set")
	}
	if o.MTLS && (o.TLSCAFile == "" || o.TLSClientCAFile == "") {
		return fmt.Errorf("mtls is enabled but no tls-ca-file is set")
	}
	return nil
}

// ApplyGlobals applies the global options to the given options. It returns the
// options for convenience.
func (global *GlobalOptions) ApplyGlobals(o *Config) (*Config, error) {
	// Protocol preferences
	o.Mesh.DisableIPv4 = global.DisableIPv4
	o.Mesh.DisableIPv6 = global.DisableIPv6
	// Gather possible endpoints
	var primaryEndpoint netip.Addr
	var detectedEndpoints endpoints.PrefixList
	var err error
	if global.PrimaryEndpoint != "" {
		primaryEndpoint, err = netip.ParseAddr(global.PrimaryEndpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to parse endpoint: %w", err)
		}
	}
	if global.DetectEndpoints || global.DetectPrivateEndpoints {
		detectedEndpoints, err = endpoints.Detect(context.Background(), endpoints.DetectOpts{
			DetectIPv6:           global.DetectIPv6,
			DetectPrivate:        global.DetectPrivateEndpoints,
			AllowRemoteDetection: global.AllowRemoteDetection,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to detect endpoints: %w", err)
		}
		sort.Sort(detectedEndpoints)
		if len(detectedEndpoints) > 0 {
			if !primaryEndpoint.IsValid() {
				primaryEndpoint = detectedEndpoints[0].Addr()
				if len(detectedEndpoints) > 1 {
					detectedEndpoints = detectedEndpoints[1:]
				} else {
					detectedEndpoints = nil
				}
			}
		}
	}

	// Apply global options

	// If the primary endpoint was detected, set it to the appropriate places
	if primaryEndpoint.IsValid() {
		// If the mesh primary endpoint was not set yet, set it
		if o.Mesh.PrimaryEndpoint == "" {
			o.Mesh.PrimaryEndpoint = primaryEndpoint.String()
		}
		// If the bootstrap advertise address was not set yet, set it
		if o.Bootstrap.Enabled && o.Bootstrap.Transport.TCPAdvertiseAddress == "" {
			_, port, err := net.SplitHostPort(o.Bootstrap.Transport.TCPListenAddress)
			if err != nil {
				return nil, fmt.Errorf("failed to parse bootstrap listen address: %w", err)
			}
			o.Bootstrap.Transport.TCPAdvertiseAddress = net.JoinHostPort(primaryEndpoint.String(), port)
		}
		// Set the wireguard endpoints if they were not configured
		if len(o.WireGuard.Endpoints) == 0 {
			var eps []string
			wgPort := o.WireGuard.ListenPort
			eps = append(eps, net.JoinHostPort(primaryEndpoint.String(), strconv.Itoa(wgPort)))
			for _, endpoint := range detectedEndpoints {
				eps = append(eps, net.JoinHostPort(endpoint.Addr().String(), strconv.Itoa(wgPort)))
			}
			o.WireGuard.Endpoints = eps
		}
		if o.Services.TURN.Enabled {
			// Grab the port from the listen address
			_, port, err := net.SplitHostPort(o.Services.TURN.ListenAddress)
			if err != nil {
				return nil, fmt.Errorf("failed to parse TURN listen address: %w", err)
			}
			// If the TURN endpoint was not set yet, set it
			if o.Services.TURN.Endpoint == "" {
				o.Services.TURN.Endpoint = "turn:" + net.JoinHostPort(primaryEndpoint.String(), port)
			}
			// Same for the public IP
			if o.Services.TURN.PublicIP == "" {
				o.Services.TURN.PublicIP = primaryEndpoint.String()
			}
		}
	}

	// Auth Configurations

	if global.MTLS {
		// Configure both client and server mTLS
		o.Auth.MTLS = MTLSOptions{
			CertFile: global.TLSCertFile,
			KeyFile:  global.TLSKeyFile,
		}
		o.Services.TLSCertFile = global.TLSCertFile
		o.Services.TLSKeyFile = global.TLSKeyFile
		o.TLS = TLSOptions{
			CAFile: global.TLSCAFile,
		}
		// Make sure the mTLS plugin is configured
		if o.Plugins.Configs == nil {
			o.Plugins.Configs = map[string]*PluginConfig{}
		}
		if o.Plugins.Configs["mtls"] == nil {
			o.Plugins.Configs["mtls"] = &PluginConfig{
				Config: map[string]any{
					"ca-file": func() string {
						if global.TLSClientCAFile != "" {
							return global.TLSClientCAFile
						}
						return global.TLSCAFile
					}(),
				},
			}
		}
	}

	// Other TLS Configurations

	if global.Insecure {
		o.TLS.Insecure = true
		o.Services.Insecure = true
	}
	if global.InsecureSkipVerify {
		o.TLS.InsecureSkipVerify = true
	}
	if global.VerifyChainOnly {
		o.TLS.VerifyChainOnly = true
	}
	if global.TLSCertFile != "" {
		o.Services.TLSCertFile = global.TLSCertFile
	}
	if global.TLSKeyFile != "" {
		o.Services.TLSKeyFile = global.TLSKeyFile
	}

	// Service advertisements

	// Set the gRPC advertise port if it is still zero.
	if o.Mesh.GRPCAdvertisePort == 0 {
		_, port, err := net.SplitHostPort(o.Services.GRPCListenAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to parse gRPC listen address: %w", err)
		}
		zport, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("failed to parse gRPC listen port: %w", err)
		}
		o.Mesh.GRPCAdvertisePort = zport
	}

	// Set the mesh DNS advertise port if it is still zero.
	if o.Services.MeshDNS.Enabled && o.Mesh.MeshDNSAdvertisePort == 0 && !o.Mesh.DisableFeatureAdvertisement {
		// TODO: We only do this for UDP for now.
		_, port, err := net.SplitHostPort(o.Services.MeshDNS.ListenUDP)
		if err != nil {
			return nil, fmt.Errorf("failed to parse meshdns listen address: %w", err)
		}
		zport, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("failed to parse meshdns listen port: %w", err)
		}
		o.Mesh.MeshDNSAdvertisePort = zport
	}

	// We do the loop again for any bridged meshes
	var meshDNSPort int
	if o.Bridge.MeshDNS.Enabled {
		_, port, err := net.SplitHostPort(o.Bridge.MeshDNS.ListenUDP)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bridge meshdns listen address: %w", err)
		}
		zport, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bridge meshdns listen port: %w", err)
		}
		meshDNSPort = zport
	}
	for _, bridgeOpts := range o.Bridge.Meshes {
		// First set the advertise port, then recurse on ApplyGlobals
		if bridgeOpts.Mesh.MeshDNSAdvertisePort == 0 {
			bridgeOpts.Mesh.MeshDNSAdvertisePort = meshDNSPort
		}
		if _, err := global.ApplyGlobals(bridgeOpts); err != nil {
			return nil, err
		}
	}

	return o, nil
}
