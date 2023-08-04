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

// Package global provides global configurations that can override others.
package global

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"

	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/meshbridge"
	"github.com/webmeshproj/webmesh/pkg/net/endpoints"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
	"github.com/webmeshproj/webmesh/pkg/plugins"
	"github.com/webmeshproj/webmesh/pkg/raft"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/util"
)

const (
	LogLevelEnvVar                    = "GLOBAL_LOG_LEVEL"
	TLSCertEnvVar                     = "GLOBAL_TLS_CERT_FILE"
	TLSKeyEnvVar                      = "GLOBAL_TLS_KEY_FILE"
	TLACAEnvVar                       = "GLOBAL_TLS_CA_FILE"
	TLSClientCAEnvVar                 = "GLOBAL_TLS_CLIENT_CA_FILE"
	MTLSEnvVar                        = "GLOBAL_MTLS"
	VerifyChainOnlyEnvVar             = "GLOBAL_VERIFY_CHAIN_ONLY"
	InsecureEnvVar                    = "GLOBAL_INSECURE"
	NoIPv4EnvVar                      = "GLOBAL_NO_IPV4"
	NoIPv6EnvVar                      = "GLOBAL_NO_IPV6"
	PrimaryEndpointEnvVar             = "GLOBAL_PRIMARY_ENDPOINT"
	EndpointsEnvVar                   = "GLOBAL_ENDPOINTS"
	DetectEndpointsEnvVar             = "GLOBAL_DETECT_ENDPOINTS"
	DetectPrivateEndpointsEnvVar      = "GLOBAL_DETECT_PRIVATE_ENDPOINTS"
	AllowRemoteDetectionEnvVar        = "GLOBAL_ALLOW_REMOTE_DETECTION"
	DetectIPv6EnvVar                  = "GLOBAL_DETECT_IPV6"
	DisableFeatureAdvertisementEnvVar = "GLOBAL_DISABLE_FEATURE_ADVERTISEMENT"
)

// Options are the global options.
type Options struct {
	// LogLevel is the log level.
	LogLevel string `yaml:"log-level,omitempty" json:"log-level,omitempty" toml:"log-level,omitempty"`
	// TLSCertFile is the TLS certificate file.
	TLSCertFile string `yaml:"tls-cert-file,omitempty" json:"tls-cert-file,omitempty" toml:"tls-cert-file,omitempty"`
	// TLSKeyFile is the TLS key file.
	TLSKeyFile string `yaml:"tls-key-file,omitempty" json:"tls-key-file,omitempty" toml:"tls-key-file,omitempty"`
	// TLACAFile is the TLS CA file.
	TLSCAFile string `yaml:"tls-ca-file,omitempty" json:"tls-ca-file,omitempty" toml:"tls-ca-file,omitempty"`
	// TLSClientCAFile is the path to the TLS client CA file.
	// If empty, either TLSCAFile or the system CA pool is used.
	TLSClientCAFile string `yaml:"tls-client-ca-file,omitempty" json:"tls-client-ca-file,omitempty" toml:"tls-client-ca-file,omitempty"`
	// MTLS is true if mutual TLS is enabled.
	MTLS bool `yaml:"mtls,omitempty" json:"mtls,omitempty" toml:"mtls,omitempty"`
	// VerifyChainOnly is true if only the chain should be verified.
	VerifyChainOnly bool `yaml:"verify-chain-only,omitempty" json:"verify-chain-only,omitempty" toml:"verify-chain-only,omitempty"`
	// Insecure is true if TLS should be disabled.
	Insecure bool `yaml:"insecure,omitempty" json:"insecure,omitempty" toml:"insecure,omitempty"`
	// NoIPv4 is true if IPv4 should be disabled.
	NoIPv4 bool `yaml:"no-ipv4,omitempty" json:"no-ipv4,omitempty" toml:"no-ipv4,omitempty"`
	// NoIPv6 is true if IPv6 should be disabled.
	NoIPv6 bool `yaml:"no-ipv6,omitempty" json:"no-ipv6,omitempty" toml:"no-ipv6,omitempty"`
	// PrimaryEndpoint is the preferred publicly routable address of this node.
	// Setting this value will override the store advertise address with its
	// configured listen port.
	PrimaryEndpoint string `yaml:"primary-endpoint,omitempty" json:"endpoint,omitempty" toml:"endpoint,omitempty"`
	// Endpoints are the additional publicly routable addresses of this node.
	// If PrimaryEndpoint is not set, it will be set to the first endpoint.
	// Setting this value will override the store advertise with its configured
	// listen port.
	Endpoints []string `yaml:"endpoints,omitempty" json:"endpoints,omitempty" toml:"endpoints,omitempty"`
	// DetectEndpoints is true if the endpoints should be detected.
	DetectEndpoints bool `yaml:"detect-endpoints,omitempty" json:"detect-endpoints,omitempty" toml:"detect-endpoints,omitempty"`
	// DetectPrivateEndpoints is true if private IP addresses should be included in detection.
	// This automatically enables DetectEndpoints.
	DetectPrivateEndpoints bool `yaml:"detect-private-endpoints,omitempty" json:"detect-private-endpoints,omitempty" toml:"detect-private-endpoints,omitempty"`
	// AllowRemoteDetection is true if remote detection is allowed.
	AllowRemoteDetection bool `yaml:"allow-remote-detection,omitempty" json:"allow-remote-detection,omitempty" toml:"allow-remote-detection,omitempty"`
	// DetectIPv6 is true if IPv6 addresses should be included in detection.
	DetectIPv6 bool `yaml:"detect-ipv6,omitempty" json:"detect-ipv6,omitempty" toml:"detect-ipv6,omitempty"`
	// DisableFeatureAdvertisement is true if feature advertisement should be disabled.
	DisableFeatureAdvertisement bool `yaml:"disable-feature-advertisement,omitempty" json:"disable-feature-advertisement,omitempty" toml:"disable-feature-advertisement,omitempty"`
}

// NewOptions creates new options.
func NewOptions() *Options {
	return &Options{
		LogLevel: "info",
	}
}

func (o *Options) BindFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.TLSCertFile, "global.tls-cert-file", util.GetEnvDefault(TLSCertEnvVar, ""),
		"The certificate file for TLS connections.")
	fs.StringVar(&o.TLSKeyFile, "global.tls-key-file", util.GetEnvDefault(TLSKeyEnvVar, ""),
		"The key file for TLS connections.")
	fs.StringVar(&o.TLSCAFile, "global.tls-ca-file", util.GetEnvDefault(TLACAEnvVar, ""),
		"The CA file for TLS connections.")
	fs.StringVar(&o.TLSClientCAFile, "global.tls-client-ca-file", util.GetEnvDefault(TLSClientCAEnvVar, ""),
		"The client CA file for TLS connections.")
	fs.BoolVar(&o.MTLS, "global.mtls", util.GetEnvDefault(MTLSEnvVar, "false") == "true",
		"Enable mutual TLS for authentication.")
	fs.BoolVar(&o.VerifyChainOnly, "global.verify-chain-only", util.GetEnvDefault(VerifyChainOnlyEnvVar, "false") == "true",
		"Only verify the TLS chain globally.")
	fs.BoolVar(&o.Insecure, "global.insecure", util.GetEnvDefault(InsecureEnvVar, "false") == "true",
		"Disable use of TLS globally.")
	fs.BoolVar(&o.NoIPv6, "global.no-ipv6", util.GetEnvDefault(NoIPv6EnvVar, "false") == "true",
		"Disable use of IPv6 globally.")
	fs.BoolVar(&o.NoIPv4, "global.no-ipv4", util.GetEnvDefault(NoIPv4EnvVar, "false") == "true",
		"Disable use of IPv4 globally.")
	fs.StringVar(&o.LogLevel, "global.log-level", util.GetEnvDefault(LogLevelEnvVar, "info"),
		"Log level (debug, info, warn, error)")

	fs.StringVar(&o.PrimaryEndpoint, "global.primary-endpoint", util.GetEnvDefault(PrimaryEndpointEnvVar, ""),
		`The preferred publicly routable address of this node. Setting this
value will override the address portion of the store advertise address. 
When detect-endpoints is true, this value will be the first address detected.`)

	fs.BoolVar(&o.DetectEndpoints, "global.detect-endpoints", util.GetEnvDefault(DetectEndpointsEnvVar, "false") == "true",
		"Detect potential endpoints from the local interfaces.")

	fs.BoolVar(&o.DetectPrivateEndpoints, "global.detect-private-endpoints", util.GetEnvDefault(DetectPrivateEndpointsEnvVar, "false") == "true",
		"Include private IP addresses in detection.")

	fs.BoolVar(&o.AllowRemoteDetection, "global.allow-remote-detection", util.GetEnvDefault(AllowRemoteDetectionEnvVar, "false") == "true",
		"Allow remote detection of endpoints.")

	fs.BoolVar(&o.DetectIPv6, "global.detect-ipv6", util.GetEnvDefault(DetectIPv6EnvVar, "false") == "true",
		"Detect IPv6 addresses. Default is to only detect IPv4.")

	fs.BoolVar(&o.DisableFeatureAdvertisement, "global.disable-feature-advertisement", util.GetEnvDefault(DisableFeatureAdvertisementEnvVar, "false") == "true",
		"Do not advertise features to the rest of the mesh.")
}

// Overlay overlays the global options onto the given option sets.
func (o *Options) Overlay(opts ...any) error {
	var primaryEndpoint netip.Addr
	var detectedEndpoints endpoints.PrefixList
	var err error
	if o.PrimaryEndpoint != "" {
		primaryEndpoint, err = netip.ParseAddr(o.PrimaryEndpoint)
		if err != nil {
			return fmt.Errorf("failed to parse endpoint: %w", err)
		}
	}
	if o.DetectEndpoints || o.DetectPrivateEndpoints {
		detectedEndpoints, err = endpoints.Detect(context.Background(), endpoints.DetectOpts{
			DetectIPv6:           o.DetectIPv6,
			DetectPrivate:        o.DetectPrivateEndpoints,
			AllowRemoteDetection: o.AllowRemoteDetection,
		})
		if err != nil {
			return fmt.Errorf("failed to detect endpoints: %w", err)
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
	for _, opt := range opts {
		switch v := opt.(type) {
		case *meshbridge.Options:
			if len(v.Meshes) == 0 {
				continue
			}
			// Meshbridge is a special case, we don't override everything
		case *mesh.Options:
			if err := o.mergeMeshOptions(v, primaryEndpoint, detectedEndpoints); err != nil {
				return err
			}
		case *services.Options:
			var meshopts *mesh.Options
			for _, inOpts := range opts {
				if vopt, ok := inOpts.(*mesh.Options); ok {
					meshopts = vopt
				}
			}
			if err := o.mergeServicesOptions(v, meshopts, primaryEndpoint); err != nil {
				return err
			}
		}
	}
	return nil
}

func (o *Options) mergeMeshOptions(opts *mesh.Options, primaryEndpoint netip.Addr, detectedEndpoints endpoints.PrefixList) error {
	o.mergePluginOptions(opts.Plugins)
	if !opts.Mesh.NoIPv4 {
		opts.Mesh.NoIPv4 = o.NoIPv4
	}
	if !opts.Mesh.NoIPv6 {
		opts.Mesh.NoIPv6 = o.NoIPv6
	}
	if !opts.TLS.Insecure {
		opts.TLS.Insecure = o.Insecure
	}
	if !opts.TLS.VerifyChainOnly {
		opts.TLS.VerifyChainOnly = o.VerifyChainOnly
	}
	if o.MTLS {
		if opts.Auth.MTLS == nil {
			opts.Auth.MTLS = &mesh.MTLSOptions{
				CertFile: o.TLSCertFile,
				KeyFile:  o.TLSKeyFile,
			}
		}
	}
	if opts.TLS.CAFile == "" {
		opts.TLS.CAFile = o.TLSCAFile
	}
	if o.MTLS && opts.Plugins.Plugins["mtls"] == nil {
		opts.Plugins.Plugins["mtls"] = &plugins.Config{
			Config: map[string]any{
				"ca-file": func() string {
					if o.TLSClientCAFile != "" {
						return o.TLSClientCAFile
					}
					return o.TLSCAFile
				}(),
			},
		}
	}
	if !primaryEndpoint.IsValid() {
		return nil
	}
	// Determine the raft and wireguard ports so we can set our
	// advertise addresses.
	var raftPort, wireguardPort uint16
	wireguardPort = uint16(opts.WireGuard.ListenPort)
	_, port, err := net.SplitHostPort(opts.Raft.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to parse raft listen address: %w", err)
	}
	raftPortz, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return fmt.Errorf("failed to parse raft listen address: %w", err)
	}
	raftPort = uint16(raftPortz)
	if raftPort == 0 {
		raftPort = raft.DefaultListenPort
	}
	if wireguardPort == 0 {
		wireguardPort = wireguard.DefaultListenPort
	}
	if opts.Mesh.PrimaryEndpoint == "" {
		opts.Mesh.PrimaryEndpoint = primaryEndpoint.String()
	}
	if len(opts.WireGuard.Endpoints) == 0 {
		var eps []string
		if primaryEndpoint.IsValid() {
			eps = append(eps, netip.AddrPortFrom(primaryEndpoint, uint16(wireguardPort)).String())
		}
		for _, endpoint := range detectedEndpoints {
			ep := netip.AddrPortFrom(endpoint.Addr(), uint16(wireguardPort)).String()
			if ep != opts.Mesh.PrimaryEndpoint {
				eps = append(eps, ep)
			}
		}
		opts.WireGuard.Endpoints = eps
	}
	if opts.Bootstrap.AdvertiseAddress == "" {
		opts.Bootstrap.AdvertiseAddress = netip.AddrPortFrom(primaryEndpoint, uint16(raftPort)).String()
	}
	return nil
}

func (o *Options) mergeServicesOptions(opts *services.Options, meshopts *mesh.Options, primaryEndpoint netip.Addr) error {
	if !opts.Insecure {
		opts.Insecure = o.Insecure
	}
	if opts.TLSCertFile == "" {
		opts.TLSCertFile = o.TLSCertFile
	}
	if opts.TLSKeyFile == "" {
		opts.TLSKeyFile = o.TLSKeyFile
	}
	if opts.TURN != nil && opts.TURN.Enabled {
		if opts.TURN.Endpoint == "" && primaryEndpoint.IsValid() {
			opts.TURN.Endpoint = fmt.Sprintf("stun:%s",
				net.JoinHostPort(primaryEndpoint.String(), strconv.Itoa(opts.TURN.ListenPort)))
		}
		if opts.TURN.PublicIP == "" && primaryEndpoint.IsValid() {
			opts.TURN.PublicIP = primaryEndpoint.String()
		}
	}
	if meshopts != nil {
		if opts.MeshDNS != nil && opts.MeshDNS.Enabled && opts.MeshDNS.ListenUDP != "" && !o.DisableFeatureAdvertisement {
			// Set the advertise DNS port
			_, port, err := net.SplitHostPort(opts.MeshDNS.ListenUDP)
			if err != nil {
				return fmt.Errorf("failed to parse listen address: %w", err)
			}
			portz, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				return fmt.Errorf("failed to parse listen address: %w", err)
			}
			meshopts.Mesh.MeshDNSPort = int(portz)
		}
	}
	return nil
}

func (o *Options) mergePluginOptions(opts *plugins.Options) {
	if o.MTLS && opts.Plugins["mtls"] == nil {
		opts.Plugins["mtls"] = &plugins.Config{
			Config: map[string]any{
				"ca-file": func() string {
					if o.TLSClientCAFile != "" {
						return o.TLSClientCAFile
					}
					return o.TLSCAFile
				}(),
			},
		}
	}
}
