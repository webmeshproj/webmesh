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

// Package webrtc contains the webmesh WebRTC service.
package webrtc

import (
	v1 "github.com/webmeshproj/api/go/v1"

	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/meshnet/wireguard"
	"github.com/webmeshproj/webmesh/pkg/services/rbac"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// DefaultSTUNServers are the default STUN servers to use.
var DefaultSTUNServers = []string{
	"stun:stun.l.google.com:19302",
}

// Server is the webmesh WebRTC service.
type Server struct {
	v1.UnimplementedWebRTCServer

	wg       wireguard.Interface
	rbacEval rbac.Evaluator
	opts     Options
}

// Options are options for the WebRTC service.
type Options struct {
	ID          types.NodeID
	Wireguard   wireguard.Interface
	NodeDialer  transport.NodeDialer
	RBAC        rbac.Evaluator
	STUNServers []string
}

// NewServer returns a new Server.
func NewServer(opts Options) *Server {
	if len(opts.STUNServers) == 0 {
		opts.STUNServers = DefaultSTUNServers
	}
	return &Server{
		wg:       opts.Wireguard,
		rbacEval: opts.RBAC,
		opts:     opts,
	}
}
