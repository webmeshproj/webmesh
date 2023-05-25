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
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"gitlab.com/webmesh/node/pkg/services"
	"gitlab.com/webmesh/node/pkg/store"
	"gitlab.com/webmesh/node/pkg/store/streamlayer"
	"gitlab.com/webmesh/node/pkg/util"
	"gitlab.com/webmesh/node/pkg/wireguard"
)

const (
	GlobalLogLevelEnvVar           = "GLOBAL_LOG_LEVEL"
	GlobalTLSCertEnvVar            = "GLOBAL_TLS_CERT_FILE"
	GlobalTLSKeyEnvVar             = "GLOBAL_TLS_KEY_FILE"
	GlobalTLACAEnvVar              = "GLOBAL_TLS_CA_FILE"
	GlobalTLSClientCAEnvVar        = "GLOBAL_TLS_CLIENT_CA_FILE"
	GlobalMTLSEnvVar               = "GLOBAL_MTLS"
	GlobalSkipVerifyHostnameEnvVar = "GLOBAL_SKIP_VERIFY_HOSTNAME"
	GlobalInsecureEnvVar           = "GLOBAL_INSECURE"
	GlobalNoIPv4EnvVar             = "GLOBAL_NO_IPV4"
	GlobalNoIPv6EnvVar             = "GLOBAL_NO_IPV6"
	GlobalEndpointEnvVar           = "GLOBAL_ENDPOINT"
	GlobalDetectEndpointEnvVar     = "GLOBAL_DETECT_ENDPOINT"
	GlobalDetectPublicIPEnvVar     = "GLOBAL_DETECT_PUBLIC_IP"
	GlobalDetectIPv6EnvVar         = "GLOBAL_DETECT_IPV6"
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
	// Endpoint is the publicly routable address of this node. Setting this value
	// will override the store advertise address and wireguard endpoints with their
	// configured listen ports.
	Endpoint string `yaml:"endpoint" json:"endpoint" toml:"endpoint"`
	// DetectEndpoint is true if the endpoint should be detected.
	DetectEndpoint bool `yaml:"detect-endpoint" json:"detect-endpoint" toml:"detect-endpoint"`
	// DetectPublicIP is true if the public IP should be detected.
	DetectPublicIP bool `yaml:"detect-public-ip" json:"detect-public-ip" toml:"detect-public-ip"`
	// DetectIPv6 is true if IPv6 should be detected.
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
	fs.BoolVar(&o.DetectEndpoint, "global.detect-endpoint", util.GetEnvDefault(GlobalDetectEndpointEnvVar, "false") == "true",
		"Detect the endpoint address.")
	fs.BoolVar(&o.DetectPublicIP, "global.detect-public-ip", util.GetEnvDefault(GlobalDetectPublicIPEnvVar, "false") == "true",
		"Detect the public IP address.")
	fs.BoolVar(&o.DetectIPv6, "global.detect-ipv6", util.GetEnvDefault(GlobalDetectIPv6EnvVar, "false") == "true",
		"Detect the IPv6 address. Default is to detect IPv4.")
	fs.StringVar(&o.Endpoint, "global.endpoint", util.GetEnvDefault(GlobalEndpointEnvVar, ""),
		`The publicly routable address of this node. Setting this value
will override the address portion of the store advertise address
and wireguard endpoints. This is only necessary if you intend for
this node's API to be reachable outside the network.`)
}

// Overlay overlays the global options onto the given option sets.
func (o *Options) Overlay(opts ...any) error {
	var endpoint netip.Addr
	var err error
	if o.Endpoint != "" {
		endpoint, err = netip.ParseAddr(o.Endpoint)
		if err != nil {
			return fmt.Errorf("failed to parse endpoint: %w", err)
		}
	}
	if o.DetectEndpoint {
		endpoint, err = o.detectEndpoint()
		if err != nil {
			return fmt.Errorf("failed to detect endpoint: %w", err)
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
			if endpoint.IsValid() {
				var raftPort uint64
				v.NodeEndpoint = endpoint.String()
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
				v.AdvertiseAddress = netip.AddrPortFrom(endpoint, uint16(raftPort)).String()
			}
		case *wireguard.Options:
			if endpoint.IsValid() {
				v.Endpoint = netip.AddrPortFrom(endpoint, uint16(v.ListenPort)).String()
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
				if v.TURNServerEndpoint == "" && endpoint.IsValid() {
					v.TURNServerEndpoint = fmt.Sprintf("stun:%s",
						net.JoinHostPort(endpoint.String(), strconv.Itoa(v.TURNServerPort)))
				}
				if v.TURNServerPublicIP == "" && endpoint.IsValid() {
					v.TURNServerPublicIP = endpoint.String()
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

func (o *Options) detectEndpoint() (netip.Addr, error) {
	if o.DetectPublicIP {
		var addr string
		var err error
		if o.DetectIPv6 {
			addr, err = util.DetectPublicIPv6(context.Background())
		} else {
			addr, err = util.DetectPublicIPv4(context.Background())
		}
		if err != nil {
			return netip.Addr{}, fmt.Errorf("failed to detect public IP: %w", err)
		}
		return netip.ParseAddr(addr)
	}
	return o.detectPrivateIP()
}

func (o *Options) detectPrivateIP() (netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to list interfaces: %w", err)
	}
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
			return netip.Addr{}, fmt.Errorf("failed to list addresses for interface %s: %w", iface.Name, err)
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				return netip.Addr{}, fmt.Errorf("failed to parse address %s: %w", addr.String(), err)
			}
			addr, err := netip.ParseAddr(ip.String())
			if err != nil {
				return netip.Addr{}, fmt.Errorf("failed to parse address %s: %w", ip.String(), err)
			}
			if o.DetectIPv6 {
				if addr.Is6() && addr.IsPrivate() {
					return addr, nil
				}
			} else {
				if addr.Is4() && addr.IsPrivate() {
					return addr, nil
				}
			}
		}
	}
	return netip.Addr{}, errors.New("no private IPv4 address found")
}
