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

// Package webrtc contains the webmesh WebRTC service.
package webrtc

import (
	"crypto/tls"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/node/pkg/meshdb/state"
	"github.com/webmeshproj/node/pkg/store"
)

// Server is the webmesh WebRTC service.
type Server struct {
	v1.UnimplementedWebRTCServer

	store       store.Store
	meshstate   state.State
	stunServers []string
	tlsConfig   *tls.Config
	log         *slog.Logger
}

// NewServer returns a new Server.
func NewServer(store store.Store, tlsConfig *tls.Config, stunServers []string) *Server {
	return &Server{
		store:       store,
		meshstate:   state.New(store),
		stunServers: stunServers,
		tlsConfig:   tlsConfig,
		log:         slog.Default().With("component", "webrtc-server"),
	}
}
