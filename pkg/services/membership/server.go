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

// Package membership contains the webmesh membership service.
package membership

import (
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb/networking"
	"github.com/webmeshproj/webmesh/pkg/meshdb/state"
	"github.com/webmeshproj/webmesh/pkg/plugins"
	"github.com/webmeshproj/webmesh/pkg/raft"
	"github.com/webmeshproj/webmesh/pkg/services/leaderproxy"
	"github.com/webmeshproj/webmesh/pkg/services/rbac"
)

// Server is the webmesh Membership service.
type Server struct {
	v1.UnimplementedMembershipServer

	raft       raft.Raft
	plugins    plugins.Manager
	rbac       rbac.Evaluator
	ipv4Prefix netip.Prefix
	ipv6Prefix netip.Prefix
	meshDomain string
	log        *slog.Logger
	mu         sync.Mutex
}

// NewServer returns a new Server.
func NewServer(raft raft.Raft, plugins plugins.Manager, rbac rbac.Evaluator) *Server {
	return &Server{
		raft:    raft,
		plugins: plugins,
		rbac:    rbac,
		log:     slog.Default().With("component", "membership-server"),
	}
}

func (s *Server) loadMeshState(ctx context.Context) error {
	var err error
	state := state.New(s.raft.Storage())
	if !s.ipv6Prefix.IsValid() {
		s.log.Debug("Looking up mesh IPv6 prefix")
		s.ipv6Prefix, err = state.GetIPv6Prefix(ctx)
		if err != nil {
			return fmt.Errorf("lookup mesh IPv6 prefix: %w", err)
		}
	}
	if !s.ipv4Prefix.IsValid() {
		s.log.Debug("Looking up mesh IPv4 prefix")
		s.ipv4Prefix, err = state.GetIPv4Prefix(ctx)
		if err != nil {
			return fmt.Errorf("lookup mesh IPv4 prefix: %w", err)
		}
	}
	if s.meshDomain == "" {
		s.log.Debug("Looking up mesh domain")
		s.meshDomain, err = state.GetMeshDomain(ctx)
		if err != nil {
			return fmt.Errorf("lookup mesh domain: %w", err)
		}
	}
	return nil
}

func (s *Server) ensurePeerRoutes(ctx context.Context, nodeID string, routes []string) (created bool, err error) {
	nw := networking.New(s.raft.Storage())
	current, err := nw.GetRoutesByNode(ctx, nodeID)
	if err != nil {
		return false, fmt.Errorf("get routes for node %q: %w", nodeID, err)
	}
Routes:
	for _, route := range routes {
		for _, r := range current {
			for _, cidr := range r.DestinationCidrs {
				if cidr == route {
					continue Routes
				}
			}
		}
		// This is a new route, start managing an auto route for the node.
		rt := v1.Route{
			Name:             nodeAutoRoute(nodeID),
			Node:             nodeID,
			DestinationCidrs: routes,
		}
		s.log.Debug("Adding new route for node", "node", nodeID, "route", &rt)
		err = nw.PutRoute(ctx, &rt)
		if err != nil {
			return true, fmt.Errorf("put route for node %q: %w", nodeID, err)
		}
		break
	}
	return false, nil
}

func nodeAutoRoute(nodeID string) string {
	return fmt.Sprintf("%s-auto", nodeID)
}

func nodeIDMatchesContext(ctx context.Context, nodeID string) bool {
	if proxiedFor, ok := leaderproxy.ProxiedFor(ctx); ok {
		return proxiedFor == nodeID
	}
	if peer, ok := context.AuthenticatedCallerFrom(ctx); ok {
		return peer == nodeID
	}
	return false
}
