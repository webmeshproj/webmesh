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

// Package node contains the webmesh node service.
package node

import (
	"crypto/tls"
	"net/netip"
	"time"

	v1 "gitlab.com/webmesh/api/v1"
	"golang.org/x/exp/slog"

	"gitlab.com/webmesh/node/pkg/meshdb/ipam"
	"gitlab.com/webmesh/node/pkg/meshdb/peers"
	"gitlab.com/webmesh/node/pkg/meshdb/state"
	"gitlab.com/webmesh/node/pkg/store"
)

// Server is the webmesh node service.
type Server struct {
	v1.UnimplementedNodeServer

	store     store.Store
	peers     peers.Peers
	ipam      ipam.IPAM
	meshstate state.State
	ulaPrefix netip.Prefix
	features  []v1.Feature
	startedAt time.Time
	log       *slog.Logger
	tlsConfig *tls.Config
}

// NewServer returns a new Server. The TLS config is optional and is used
// for RPCs to other nodes in the cluster. Features are used for returning
// what features are enabled. It is the callers responsibility to ensure
// those servers are registered on the node.
func NewServer(store store.Store, tlsConfig *tls.Config, features []v1.Feature) *Server {
	return &Server{
		store:     store,
		peers:     peers.New(store),
		ipam:      ipam.New(store),
		meshstate: state.New(store),
		features:  features,
		startedAt: time.Now(),
		log:       slog.Default().With("component", "node-server"),
	}
}
