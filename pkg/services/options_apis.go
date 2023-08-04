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
	"strings"

	"github.com/webmeshproj/webmesh/pkg/util"
)

const (
	LeaderProxyDisabledEnvVar  = "SERVICES_API_DISABLE_LEADER_PROXY"
	MeshEnabledEnvVar          = "SERVICES_API_MESH"
	AdminEnabledEnvVar         = "SERVICES_API_ADMIN"
	PeerDiscoveryEnabledEnvVar = "SERVICES_API_PEER_DISCOVERY"
	WebRTCEnabledEnvVar        = "SERVICES_API_WEBRTC"
	WebRTCSTUNServersEnvVar    = "SERVICES_API_STUN_SERVERS"
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
}

// NewAPIOptions creates a new APIOptions with default values.
func NewAPIOptions() *APIOptions {
	return &APIOptions{
		STUNServers: "stun:stun.l.google.com:19302",
	}
}

// BindFlags binds the flags. The options are returned
func (o *APIOptions) BindFlags(fs *flag.FlagSet, prefix ...string) {
	var p string
	if len(prefix) > 0 {
		p = strings.Join(prefix, ".") + "."
	}
	fs.BoolVar(&o.DisableLeaderProxy, p+"services.api.disable-leader-proxy", util.GetEnvDefault(LeaderProxyDisabledEnvVar, "false") == "true",
		"Disable the leader proxy.")
	fs.BoolVar(&o.Admin, p+"services.api.admin", util.GetEnvDefault(AdminEnabledEnvVar, "false") == "true",
		"Enable the admin API.")
	fs.BoolVar(&o.Mesh, p+"services.api.mesh", util.GetEnvDefault(MeshEnabledEnvVar, "false") == "true",
		"Enable the mesh API.")
	fs.BoolVar(&o.PeerDiscovery, p+"services.api.peer-discovery", util.GetEnvDefault(PeerDiscoveryEnabledEnvVar, "false") == "true",
		"Enable the peer discovery API.")
	fs.BoolVar(&o.WebRTC, p+"services.api.webrtc", util.GetEnvDefault(WebRTCEnabledEnvVar, "false") == "true",
		"Enable the WebRTC API.")
	fs.StringVar(&o.STUNServers, p+"services.api.stun-servers", util.GetEnvDefault(WebRTCSTUNServersEnvVar, "stun:stun.l.google.com:19302"),
		"STUN servers to use.")
}

// Validate validates the options.
func (o *APIOptions) Validate() error {
	if o.WebRTC && o.STUNServers == "" {
		return errors.New("STUN servers must be specified if the WebRTC API is enabled")
	}
	return nil
}
