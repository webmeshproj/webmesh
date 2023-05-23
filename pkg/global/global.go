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
	"flag"

	"gitlab.com/webmesh/node/pkg/services"
	"gitlab.com/webmesh/node/pkg/store"
	"gitlab.com/webmesh/node/pkg/store/streamlayer"
	"gitlab.com/webmesh/node/pkg/util"
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
)

// Opts are the global options.
type Opts struct {
	// LogLevel is the log level.
	LogLevel string
	// TLSCertFile is the TLS certificate file.
	TLSCertFile string
	// TLSKeyFile is the TLS key file.
	TLSKeyFile string
	// TLACAFile is the TLS CA file.
	TLSCAFile string
	// TLSClientCAFile is the path to the TLS client CA file.
	// If empty, either TLSCAFile or the system CA pool is used.
	TLSClientCAFile string
	// MTLS is true if mutual TLS is enabled.
	MTLS bool
	// SkipVerifyHostname is true if the hostname should not be verified.
	SkipVerifyHostname bool
	// Insecure is true if TLS should be disabled.
	Insecure bool
	// NoIPv4 is true if IPv4 should be disabled.
	NoIPv4 bool
	// NoIPv6 is true if IPv6 should be disabled.
	NoIPv6 bool
}

// NewOptions creates new options.
func NewOptions() *Opts {
	return &Opts{
		LogLevel: "info",
	}
}

func (o *Opts) BindFlags(fs *flag.FlagSet) {
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
}

// Overlay overlays the global options onto the given option sets.
func (o *Opts) Overlay(opts ...any) {
	for _, opt := range opts {
		switch v := opt.(type) {
		case *store.Options:
			if !v.NoIPv4 {
				v.NoIPv4 = o.NoIPv4
			}
			if !v.NoIPv6 {
				v.NoIPv6 = o.NoIPv6
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
}
