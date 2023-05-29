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

// Package global provides global configurations that can override others.
package global

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/webmeshproj/node/pkg/services"
	"github.com/webmeshproj/node/pkg/store"
	"github.com/webmeshproj/node/pkg/store/streamlayer"
	"github.com/webmeshproj/node/pkg/util"
)

const (
	GlobalLogLevelEnvVar               = "GLOBAL_LOG_LEVEL"
	GlobalTLSCertEnvVar                = "GLOBAL_TLS_CERT_FILE"
	GlobalTLSKeyEnvVar                 = "GLOBAL_TLS_KEY_FILE"
	GlobalTLACAEnvVar                  = "GLOBAL_TLS_CA_FILE"
	GlobalTLSClientCAEnvVar            = "GLOBAL_TLS_CLIENT_CA_FILE"
	GlobalMTLSEnvVar                   = "GLOBAL_MTLS"
	GlobalSkipVerifyHostnameEnvVar     = "GLOBAL_SKIP_VERIFY_HOSTNAME"
	GlobalInsecureEnvVar               = "GLOBAL_INSECURE"
	GlobalNoIPv4EnvVar                 = "GLOBAL_NO_IPV4"
	GlobalNoIPv6EnvVar                 = "GLOBAL_NO_IPV6"
	GlobalPrimaryEndpointEnvVar        = "GLOBAL_PRIMARY_ENDPOINT"
	GlobalEndpointsEnvVar              = "GLOBAL_ENDPOINTS"
	GlobalDetectEndpointsEnvVar        = "GLOBAL_DETECT_ENDPOINTS"
	GlobalDetectPrivateEndpointsEnvVar = "GLOBAL_DETECT_PRIVATE_ENDPOINTS"
	GlobalAllowRemoteDetectionEnvVar   = "GLOBAL_ALLOW_REMOTE_DETECTION"
	GlobalDetectIPv6EnvVar             = "GLOBAL_DETECT_IPV6"
)

// Options are the global options.
type Options struct {
	// LogLevel is the log level.
	LogLevel string `yaml:"log-level" json:"log-level" toml:"log-level"`
	// TLSCertFile is the TLS certificate file.
	TLSCertFile string `yaml:"tls-cert-file" json:"tls-cert-file" toml:"tls-cert-file"`
	// TLSKeyFile is the TLS key file.
	TLSKeyFile string `yaml:"tls-key-file" json:"tls-key-file" toml:"tls-key-file"`
	// TLACAFile is the TLS CA file.
	TLSCAFile string `yaml:"tls-ca-file" json:"tls-ca-file" toml:"tls-ca-file"`
	// TLSClientCAFile is the path to the TLS client CA file.
	// If empty, either TLSCAFile or the system CA pool is used.
	TLSClientCAFile string `yaml:"tls-client-ca-file" json:"tls-client-ca-file" toml:"tls-client-ca-file"`
	// MTLS is true if mutual TLS is enabled.
	MTLS bool `yaml:"mtls" json:"mtls" toml:"mtls"`
	// SkipVerifyHostname is true if the hostname should not be verified.
	SkipVerifyHostname bool `yaml:"skip-verify-hostname" json:"skip-verify-hostname" toml:"skip-verify-hostname"`
	// Insecure is true if TLS should be disabled.
	Insecure bool `yaml:"insecure" json:"insecure" toml:"insecure"`
	// NoIPv4 is true if IPv4 should be disabled.
	NoIPv4 bool `yaml:"no-ipv4" json:"no-ipv4" toml:"no-ipv4"`
	// NoIPv6 is true if IPv6 should be disabled.
	NoIPv6 bool `yaml:"no-ipv6" json:"no-ipv6" toml:"no-ipv6"`
	// PrimaryEndpoint is the preferred publicly routable address of this node.
	// Setting this value will override the store advertise address with its
	// configured listen port.
	PrimaryEndpoint string `yaml:"primary-endpoint" json:"endpoint" toml:"endpoint"`
	// Endpoints are the additional publicly routable addresses of this node.
	// If PrimaryEndpoint is not set, it will be set to the first endpoint.
	// Setting this value will override the store advertise with its configured
	// listen port.
	Endpoints []string `yaml:"endpoints" json:"endpoints" toml:"endpoints"`
	// DetectEndpoints is true if the endpoints should be detected.
	DetectEndpoints bool `yaml:"detect-endpoints" json:"detect-endpoints" toml:"detect-endpoints"`
	// DetectPrivateEndpoints is true if private IP addresses should be included in detection.
	DetectPrivateEndpoints bool `yaml:"detect-private-endpoints" json:"detect-private-endpoints" toml:"detect-private-endpoints"`
	// AllowRemoteDetection is true if remote detection is allowed.
	AllowRemoteDetection bool `yaml:"allow-remote-detection" json:"allow-remote-detection" toml:"allow-remote-detection"`
	// DetectIPv6 is true if IPv6 addresses should be included in detection.
	DetectIPv6 bool `yaml:"detect-ipv6" json:"detect-ipv6" toml:"detect-ipv6"`
}

// NewOptions creates new options.
func NewOptions() *Options {
	return &Options{
		LogLevel: "info",
	}
}

func (o *Options) BindFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.TLSCertFile, "global.tls-cert-file", util.GetEnvDefault(GlobalTLSCertEnvVar, ""),
		"The certificate file for TLS connections.")
	fs.StringVar(&o.TLSKeyFile, "global.tls-key-file", util.GetEnvDefault(GlobalTLSKeyEnvVar, ""),
		"The key file for TLS connections.")
	fs.StringVar(&o.TLSCAFile, "global.tls-ca-file", util.GetEnvDefault(GlobalTLACAEnvVar, ""),
		"The CA file for TLS connections.")
	fs.StringVar(&o.TLSClientCAFile, "global.tls-client-ca-file", util.GetEnvDefault(GlobalTLSClientCAEnvVar, ""),
		"The client CA file for TLS connections.")
	fs.BoolVar(&o.MTLS, "global.mtls", util.GetEnvDefault(GlobalMTLSEnvVar, "false") == "true",
		"Enable mutual TLS globally.")
	fs.BoolVar(&o.SkipVerifyHostname, "global.skip-verify-hostname", util.GetEnvDefault(GlobalSkipVerifyHostnameEnvVar, "false") == "true",
		"Disable hostname verification globally.")
	fs.BoolVar(&o.Insecure, "global.insecure", util.GetEnvDefault(GlobalInsecureEnvVar, "false") == "true",
		"Disable use of TLS globally.")
	fs.BoolVar(&o.NoIPv6, "global.no-ipv6", util.GetEnvDefault(GlobalNoIPv6EnvVar, "false") == "true",
		"Disable use of IPv6 globally.")
	fs.BoolVar(&o.NoIPv4, "global.no-ipv4", util.GetEnvDefault(GlobalNoIPv4EnvVar, "false") == "true",
		"Disable use of IPv4 globally.")
	fs.StringVar(&o.LogLevel, "global.log-level", util.GetEnvDefault(GlobalLogLevelEnvVar, "info"),
		"Log level (debug, info, warn, error)")

	fs.StringVar(&o.PrimaryEndpoint, "global.primary-endpoint", util.GetEnvDefault(GlobalPrimaryEndpointEnvVar, ""),
		`The preferred publicly routable address of this node. Setting this
value will override the address portion of the store advertise address. 
When detect-endpoints is true, this value will be the first address detected.`)

	fs.BoolVar(&o.DetectEndpoints, "global.detect-endpoints", util.GetEnvDefault(GlobalDetectEndpointsEnvVar, "false") == "true",
		"Detect potential endpoints from the local interfaces.")

	fs.BoolVar(&o.DetectPrivateEndpoints, "global.detect-private-endpoints", util.GetEnvDefault(GlobalDetectPrivateEndpointsEnvVar, "false") == "true",
		"Include private IP addresses in detection.")

	fs.BoolVar(&o.AllowRemoteDetection, "global.allow-remote-detection", util.GetEnvDefault(GlobalAllowRemoteDetectionEnvVar, "false") == "true",
		"Allow remote detection of endpoints.")

	fs.BoolVar(&o.DetectIPv6, "global.detect-ipv6", util.GetEnvDefault(GlobalDetectIPv6EnvVar, "false") == "true",
		"Detect IPv6 addresses. Default is to only detect IPv4.")
}

// Overlay overlays the global options onto the given option sets.
func (o *Options) Overlay(opts ...any) error {
	var primaryEndpoint netip.Addr
	var endpoints []netip.Addr
	var err error
	if o.PrimaryEndpoint != "" {
		primaryEndpoint, err = netip.ParseAddr(o.PrimaryEndpoint)
		if err != nil {
			return fmt.Errorf("failed to parse endpoint: %w", err)
		}
	}
	if o.DetectEndpoints {
		endpoints, err = o.detectEndpoints()
		if err != nil {
			return fmt.Errorf("failed to detect endpoints: %w", err)
		}
		if len(endpoints) > 0 {
			if !primaryEndpoint.IsValid() {
				primaryEndpoint = endpoints[0]
				if len(endpoints) > 1 {
					endpoints = endpoints[1:]
				} else {
					endpoints = nil
				}
			}
		}
	}
	for _, opt := range opts {
		switch v := opt.(type) {
		case *store.Options:
			if !v.NoIPv4 {
				v.NoIPv4 = o.NoIPv4
			}
			if !v.NoIPv6 {
				v.NoIPv6 = o.NoIPv6
			}
			if primaryEndpoint.IsValid() {
				var raftPort uint64
				for _, inOpts := range opts {
					if vopt, ok := inOpts.(*streamlayer.Options); ok {
						_, port, err := net.SplitHostPort(vopt.ListenAddress)
						if err != nil {
							return fmt.Errorf("failed to parse raft listen address: %w", err)
						}
						raftPort, _ = strconv.ParseUint(port, 10, 16)
						break
					}
				}
				if raftPort == 0 {
					raftPort = 9443
				}
				if v.NodeEndpoint == "" {
					v.NodeEndpoint = primaryEndpoint.String()
				}
				if v.NodeAdditionalEndpoints == "" && len(endpoints) > 0 {
					v.NodeAdditionalEndpoints = strings.Join(toAddrList(endpoints), ",")
				}
				v.AdvertiseAddress = netip.AddrPortFrom(primaryEndpoint, uint16(raftPort)).String()
			}
		case *services.Options:
			if !v.Insecure {
				v.Insecure = o.Insecure
			}
			if !v.MTLS {
				v.MTLS = o.MTLS
			}
			if !v.SkipVerifyHostname {
				v.SkipVerifyHostname = o.SkipVerifyHostname
			}
			if v.TLSCertFile == "" {
				v.TLSCertFile = o.TLSCertFile
			}
			if v.TLSKeyFile == "" {
				v.TLSKeyFile = o.TLSKeyFile
			}
			if v.TLSCAFile == "" {
				v.TLSCAFile = o.TLSCAFile
			}
			if v.TLSClientCAFile == "" {
				v.TLSClientCAFile = o.TLSClientCAFile
			}
			if v.EnableTURNServer {
				if v.TURNServerEndpoint == "" && primaryEndpoint.IsValid() {
					v.TURNServerEndpoint = fmt.Sprintf("stun:%s",
						net.JoinHostPort(primaryEndpoint.String(), strconv.Itoa(v.TURNServerPort)))
				}
				if v.TURNServerPublicIP == "" && primaryEndpoint.IsValid() {
					v.TURNServerPublicIP = primaryEndpoint.String()
				}
			}
		case *streamlayer.Options:
			if !v.Insecure {
				v.Insecure = o.Insecure
			}
			if !v.MTLS {
				v.MTLS = o.MTLS
			}
			if !v.SkipVerifyHostname {
				v.SkipVerifyHostname = o.SkipVerifyHostname
			}
			if v.TLSCertFile == "" {
				v.TLSCertFile = o.TLSCertFile
			}
			if v.TLSKeyFile == "" {
				v.TLSKeyFile = o.TLSKeyFile
			}
			if v.TLSCAFile == "" {
				v.TLSCAFile = o.TLSCAFile
			}
			if v.TLSClientCAFile == "" {
				v.TLSClientCAFile = o.TLSClientCAFile
			}
		}
	}
	return nil
}

func (o *Options) detectEndpoints() ([]netip.Addr, error) {
	addrs, err := o.detectFromInterfaces()
	if err != nil {
		return nil, err
	}
	if o.AllowRemoteDetection && len(addrs) == 0 {
		var addr string
		if o.DetectIPv6 {
			addr, err = util.DetectPublicIPv6(context.Background())
		} else {
			addr, err = util.DetectPublicIPv4(context.Background())
		}
		if err != nil {
			return nil, fmt.Errorf("failed to detect public address: %w", err)
		}
		parsed, err := netip.ParseAddr(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public address: %w", err)
		}
		addrs = append(addrs, parsed)
	}
	return addrs, nil
}

func (o *Options) detectFromInterfaces() ([]netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list interfaces: %w", err)
	}
	var ips []netip.Addr
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("failed to list addresses for interface %s: %w", iface.Name, err)
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				return nil, fmt.Errorf("failed to parse address %s: %w", addr.String(), err)
			}
			addr, err := netip.ParseAddr(ip.String())
			if err != nil {
				return nil, fmt.Errorf("failed to parse address %s: %w", ip.String(), err)
			}
			if addr.IsPrivate() && !o.DetectPrivateEndpoints {
				continue
			}
			if o.DetectIPv6 {
				if addr.Is6() {
					ips = append(ips, addr)
				}
			} else {
				if addr.Is4() && addr.IsPrivate() {
					ips = append(ips, addr)
				}
			}
		}
	}
	return ips, nil
}

func toAddrList(eps []netip.Addr) []string {
	var out []string
	for _, ep := range eps {
		out = append(out, ep.String())
	}
	return out
}
