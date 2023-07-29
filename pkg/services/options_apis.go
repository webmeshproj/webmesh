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

package services

import (
	"errors"
	"flag"

	"github.com/webmeshproj/webmesh/pkg/util"
)

const (
	LeaderProxyDisabledEnvVar     = "SERVICES_API_DISABLE_LEADER_PROXY"
	MeshEnabledEnvVar             = "SERVICES_API_MESH"
	AdminEnabledEnvVar            = "SERVICES_API_ADMIN"
	PeerDiscoveryEnabledEnvVar    = "SERVICES_API_PEER_DISCOVERY"
	WebRTCEnabledEnvVar           = "SERVICES_API_WEBRTC"
	WebRTCSTUNServersEnvVar       = "SERVICES_API_STUN_SERVERS"
	ProxyTLSCertFileEnvVar        = "SERVICES_API_PROXY_TLS_CERT_FILE"
	ProxyTLSKeyFileEnvVar         = "SERVICES_API_PROXY_TLS_KEY_FILE"
	ProxyTLSCAFileEnvVar          = "SERVICES_API_PROXY_TLS_CA_FILE"
	ProxyVerifyChainOnlyEnvVar    = "SERVICES_API_PROXY_VERIFY_CHAIN_ONLY"
	ProxyInsecureSkipVerifyEnvVar = "SERVICES_API_PROXY_INSECURE_SKIP_VERIFY"
	ProxyInsecureEnvVar           = "SERVICES_API_PROXY_INSECURE"
)

// APIOptions are the options for which APIs to register and expose.
type APIOptions struct {
	// DisableLeaderProxy is true if the leader proxy should be disabled.
	DisableLeaderProxy bool `json:"disable-leader-proxy,omitempty" yaml:"disable-leader-proxy,omitempty" toml:"disable-leader-proxy,omitempty"`
	// Mesh is true if the mesh API should be registered.
	Mesh bool `json:"mesh,omitempty" yaml:"mesh,omitempty" toml:"mesh,omitempty"`
	// Admin is true if the admin API should be registered.
	Admin bool `json:"admin,omitempty" yaml:"admin,omitempty" toml:"admin,omitempty"`
	// PeerDiscovery is true if the peer discovery API should be registered.
	PeerDiscovery bool `json:"peer-discovery,omitempty" yaml:"peer-discovery,omitempty" toml:"peer-discovery,omitempty"`
	// WebRTC is true if the WebRTC API should be registered.
	WebRTC bool `json:"webrtc,omitempty" yaml:"webrtc,omitempty" toml:"webrtc,omitempty"`
	// STUNServers is a comma separated list of STUN servers to use if the WebRTC API is enabled.
	STUNServers string `json:"stun-servers,omitempty" yaml:"stun-servers,omitempty" toml:"stun-servers,omitempty"`
	// ProxyAuth are options for authenticating the proxy transport.
	ProxyAuth *ProxyAuth `json:"proxy-auth,omitempty" yaml:"proxy-auth,omitempty" toml:"proxy-auth,omitempty"`
	// ProxyTLSCAFile is the path to the TLS CA file for verifying a peer node's certificate.
	ProxyTLSCAFile string `json:"proxy-tls-ca-file,omitempty" yaml:"proxy-tls-ca-file,omitempty" toml:"proxy-tls-ca-file,omitempty"`
	// ProxyVerifyChainOnly is true if only the chain should be verified when proxying connections.
	ProxyVerifyChainOnly bool `json:"proxy-verify-chain-only,omitempty" yaml:"proxy-verify-chain-only,omitempty" toml:"proxy-verify-chain-only,omitempty"`
	// ProxyInsecureSkipVerify is true if TLS verification should be skipped when proxying connections.
	ProxyInsecureSkipVerify bool `json:"proxy-insecure-skip-verify,omitempty" yaml:"proxy-insecure-skip-verify,omitempty" toml:"proxy-insecure-skip-verify,omitempty"`
	// ProxyInsecure is true if the proxy transport is insecure.
	ProxyInsecure bool `json:"proxy-insecure,omitempty" yaml:"proxy-insecure,omitempty" toml:"proxy-insecure,omitempty"`
}

// ProxyAuth are options for authenticating the proxy transport.
type ProxyAuth struct {
	// Basic are options for basic authentication.
	Basic *BasicAuthOptions `json:"basic,omitempty" yaml:"basic,omitempty" toml:"basic,omitempty"`
	// MTLS are options for mutual TLS.
	MTLS *MTLSOptions `json:"mtls,omitempty" yaml:"mtls,omitempty" toml:"mtls,omitempty"`
	// LDAP are options for LDAP authentication.
	LDAP *LDAPAuthOptions `json:"ldap,omitempty" yaml:"ldap,omitempty" toml:"ldap,omitempty"`
}

// MTLSOptions are options for mutual TLS.
type MTLSOptions struct {
	// TLSCertFile is the path to a TLS certificate file to present when joining.
	CertFile string `yaml:"cert-file,omitempty" json:"cert-file,omitempty" toml:"cert-file,omitempty"`
	// TLSKeyFile is the path to a TLS key file for the certificate.
	KeyFile string `yaml:"key-file,omitempty" json:"key-file,omitempty" toml:"tls-file,omitempty"`
}

// BasicAuthOptions are options for basic authentication.
type BasicAuthOptions struct {
	// Username is the username.
	Username string `json:"username,omitempty" yaml:"username,omitempty" toml:"username,omitempty"`
	// Password is the password.
	Password string `json:"password,omitempty" yaml:"password,omitempty" toml:"password,omitempty"`
}

// LDAPAuthOptions are options for LDAP authentication.
type LDAPAuthOptions struct {
	// Username is the username.
	Username string `json:"username,omitempty" yaml:"username,omitempty" toml:"username,omitempty"`
	// Password is the password.
	Password string `json:"password,omitempty" yaml:"password,omitempty" toml:"password,omitempty"`
}

// NewAPIOptions creates a new APIOptions with default values.
func NewAPIOptions() *APIOptions {
	return &APIOptions{
		STUNServers: "stun:stun.l.google.com:19302",
	}
}

// BindFlags binds the flags. The options are returned
func (o *APIOptions) BindFlags(fs *flag.FlagSet) {
	fs.BoolVar(&o.DisableLeaderProxy, "services.api.disable-leader-proxy", util.GetEnvDefault(LeaderProxyDisabledEnvVar, "false") == "true",
		"Disable the leader proxy.")
	fs.BoolVar(&o.Admin, "services.api.admin", util.GetEnvDefault(AdminEnabledEnvVar, "false") == "true",
		"Enable the admin API.")
	fs.BoolVar(&o.Mesh, "services.api.mesh", util.GetEnvDefault(MeshEnabledEnvVar, "false") == "true",
		"Enable the mesh API.")
	fs.BoolVar(&o.PeerDiscovery, "services.api.peer-discovery", util.GetEnvDefault(PeerDiscoveryEnabledEnvVar, "false") == "true",
		"Enable the peer discovery API.")
	fs.BoolVar(&o.WebRTC, "services.api.webrtc", util.GetEnvDefault(WebRTCEnabledEnvVar, "false") == "true",
		"Enable the WebRTC API.")
	fs.StringVar(&o.STUNServers, "services.api.stun-servers", util.GetEnvDefault(WebRTCSTUNServersEnvVar, "stun:stun.l.google.com:19302"),
		"STUN servers to use.")
	fs.StringVar(&o.ProxyTLSCAFile, "services.api.proxy-tls-ca-file", util.GetEnvDefault(ProxyTLSCAFileEnvVar, ""),
		"Path to the TLS CA file for verifying the peer certificates.")
	fs.BoolVar(&o.ProxyVerifyChainOnly, "services.api.proxy-verify-chain-only", util.GetEnvDefault(ProxyVerifyChainOnlyEnvVar, "false") == "true",
		"Only verify the TLS chain when proxying connections.")
	fs.BoolVar(&o.ProxyInsecureSkipVerify, "services.api.proxy-insecure-skip-verify", util.GetEnvDefault(ProxyInsecureSkipVerifyEnvVar, "false") == "true",
		"Skip TLS verification when proxying connections.")
	fs.BoolVar(&o.ProxyInsecure, "services.api.proxy-insecure", util.GetEnvDefault(ProxyInsecureEnvVar, "false") == "true",
		"Don't use TLS for the leader proxy.")
	fs.Func("services.api.proxy-auth.mtls.cert-file", "Path to a TLS certificate file to present when joining.", func(s string) error {
		if o.ProxyAuth == nil {
			o.ProxyAuth = &ProxyAuth{}
		}
		if o.ProxyAuth.MTLS == nil {
			o.ProxyAuth.MTLS = &MTLSOptions{}
		}
		o.ProxyAuth.MTLS.CertFile = s
		return nil
	})
	fs.Func("services.api.proxy-auth.mtls.key-file", "Path to a TLS key file for the certificate.", func(s string) error {
		if o.ProxyAuth == nil {
			o.ProxyAuth = &ProxyAuth{}
		}
		if o.ProxyAuth.MTLS == nil {
			o.ProxyAuth.MTLS = &MTLSOptions{}
		}
		o.ProxyAuth.MTLS.KeyFile = s
		return nil
	})
	fs.Func("services.api.proxy-auth.basic.username", "Username for basic authentication.", func(s string) error {
		if o.ProxyAuth == nil {
			o.ProxyAuth = &ProxyAuth{}
		}
		if o.ProxyAuth.Basic == nil {
			o.ProxyAuth.Basic = &BasicAuthOptions{}
		}
		o.ProxyAuth.Basic.Username = s
		return nil
	})
	fs.Func("services.api.proxy-auth.basic.password", "Password for basic authentication.", func(s string) error {
		if o.ProxyAuth == nil {
			o.ProxyAuth = &ProxyAuth{}
		}
		if o.ProxyAuth.Basic == nil {
			o.ProxyAuth.Basic = &BasicAuthOptions{}
		}
		o.ProxyAuth.Basic.Password = s
		return nil
	})
	fs.Func("services.api.proxy-auth.ldap.username", "Username for LDAP authentication.", func(s string) error {
		if o.ProxyAuth == nil {
			o.ProxyAuth = &ProxyAuth{}
		}
		if o.ProxyAuth.LDAP == nil {
			o.ProxyAuth.LDAP = &LDAPAuthOptions{}
		}
		o.ProxyAuth.LDAP.Username = s
		return nil
	})
}

// Validate validates the options.
func (o *APIOptions) Validate() error {
	if o.WebRTC && o.STUNServers == "" {
		return errors.New("STUN servers must be specified if the WebRTC API is enabled")
	}
	return nil
}
