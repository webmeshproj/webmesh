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

	"github.com/webmeshproj/node/pkg/util"
)

const (
	LeaderProxyEnabledEnvVar      = "SERVICES_API_LEADER_PROXY"
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
	// LeaderProxy is true if the leader proxy API should be registered.
	LeaderProxy bool `json:"leader-proxy,omitempty" yaml:"leader-proxy,omitempty" toml:"leader-proxy,omitempty"`
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
	// ProxyTLSCertFile is the path to the TLS certificate file for the proxy transport. If left unset,
	// the server certificate will be used.
	ProxyTLSCertFile string `json:"proxy-tls-cert-file,omitempty" yaml:"proxy-tls-cert-file,omitempty" toml:"proxy-tls-cert-file,omitempty"`
	// ProxyTLSKeyFile is the path to the TLS key file for the proxy transport. If left unset,
	// the server key will be used.
	ProxyTLSKeyFile string `json:"proxy-tls-key-file,omitempty" yaml:"proxy-tls-key-file,omitempty" toml:"proxy-tls-key-file,omitempty"`
	// ProxyTLSCAFile is the path to the TLS CA file for verifying a peer node's certificate.
	ProxyTLSCAFile string `json:"proxy-tls-ca-file,omitempty" yaml:"proxy-tls-ca-file,omitempty" toml:"proxy-tls-ca-file,omitempty"`
	// ProxyVerifyChainOnly is true if only the chain should be verified when proxying connections.
	ProxyVerifyChainOnly bool `json:"proxy-verify-chain-only,omitempty" yaml:"proxy-verify-chain-only,omitempty" toml:"proxy-verify-chain-only,omitempty"`
	// ProxyInsecureSkipVerify is true if TLS verification should be skipped when proxying connections.
	ProxyInsecureSkipVerify bool `json:"proxy-insecure-skip-verify,omitempty" yaml:"proxy-insecure-skip-verify,omitempty" toml:"proxy-insecure-skip-verify,omitempty"`
	// ProxyInsecure is true if the proxy transport is insecure.
	ProxyInsecure bool `json:"proxy-insecure,omitempty" yaml:"proxy-insecure,omitempty" toml:"proxy-insecure,omitempty"`
}

// NewAPIOptions creates a new APIOptions with default values.
func NewAPIOptions() *APIOptions {
	return &APIOptions{
		STUNServers: "stun:stun.l.google.com:19302",
	}
}

// BindFlags binds the flags. The options are returned
func (o *APIOptions) BindFlags(fs *flag.FlagSet) {
	fs.BoolVar(&o.LeaderProxy, "services.api.leader-proxy", util.GetEnvDefault(LeaderProxyEnabledEnvVar, "false") == "true",
		"Enable the leader proxy.")
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
	fs.StringVar(&o.ProxyTLSCertFile, "services.api.proxy-tls-cert-file", util.GetEnvDefault(ProxyTLSCertFileEnvVar, ""),
		"Path to the TLS certificate file for proxying.")
	fs.StringVar(&o.ProxyTLSKeyFile, "services.api.proxy-tls-key-file", util.GetEnvDefault(ProxyTLSKeyFileEnvVar, ""),
		"Path to the TLS key file for proxying.")
	fs.StringVar(&o.ProxyTLSCAFile, "services.api.proxy-tls-ca-file", util.GetEnvDefault(ProxyTLSCAFileEnvVar, ""),
		"Path to the TLS CA file for verifying the peer certificates.")
	fs.BoolVar(&o.ProxyVerifyChainOnly, "services.api.proxy-verify-chain-only", util.GetEnvDefault(ProxyVerifyChainOnlyEnvVar, "false") == "true",
		"Only verify the TLS chain when proxying connections.")
	fs.BoolVar(&o.ProxyInsecureSkipVerify, "services.api.proxy-insecure-skip-verify", util.GetEnvDefault(ProxyInsecureSkipVerifyEnvVar, "false") == "true",
		"Skip TLS verification when proxying connections.")
	fs.BoolVar(&o.ProxyInsecure, "services.api.proxy-insecure", util.GetEnvDefault(ProxyInsecureEnvVar, "false") == "true",
		"Don't use TLS for the leader proxy.")
}

// Validate validates the options.
func (o *APIOptions) Validate() error {
	if o.WebRTC && o.STUNServers == "" {
		return errors.New("STUN servers must be specified if the WebRTC API is enabled")
	}
	return nil
}
