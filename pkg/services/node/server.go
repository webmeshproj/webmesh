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
	"net/netip"

	v1 "gitlab.com/webmesh/api/v1"
	"golang.org/x/exp/slog"

	"gitlab.com/webmesh/node/pkg/services/node/ipam"
	"gitlab.com/webmesh/node/pkg/services/node/peers"
	"gitlab.com/webmesh/node/pkg/store"
)

// Server is the webmesh node service.
type Server struct {
	v1.UnimplementedNodeServer

	store     store.Store
	peers     peers.Peers
	ipam      ipam.IPAM
	ulaPrefix netip.Prefix

	log *slog.Logger
}

// NewServer returns a new Server.
func NewServer(store store.Store) *Server {
	return &Server{
		store: store,
		peers: peers.New(store),
		ipam:  ipam.New(store),
		log:   slog.Default().With("component", "node-server"),
	}
}
