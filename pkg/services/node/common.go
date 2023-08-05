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

package node

import (
	"fmt"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/services/leaderproxy"
)

func (s *Server) ensurePeerRoutes(ctx context.Context, nodeID string, routes []string) (created bool, err error) {
	current, err := s.networking.GetRoutesByNode(ctx, nodeID)
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
		context.LoggerFrom(ctx).Debug("adding new route for node", "node", nodeID, "route", &rt)
		err = s.networking.PutRoute(ctx, &rt)
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

func (s *Server) loadMeshState(ctx context.Context) error {
	var err error
	if !s.ipv6Prefix.IsValid() {
		context.LoggerFrom(ctx).Debug("looking up mesh IPv6 prefix")
		s.ipv6Prefix, err = s.meshstate.GetIPv6Prefix(ctx)
		if err != nil {
			return fmt.Errorf("lookup mesh IPv6 prefix: %w", err)
		}
	}
	if !s.ipv4Prefix.IsValid() {
		context.LoggerFrom(ctx).Debug("looking up mesh IPv4 prefix")
		s.ipv4Prefix, err = s.meshstate.GetIPv4Prefix(ctx)
		if err != nil {
			return fmt.Errorf("lookup mesh IPv4 prefix: %w", err)
		}
	}
	if s.meshDomain == "" {
		context.LoggerFrom(ctx).Debug("looking up mesh domain")
		s.meshDomain, err = s.meshstate.GetMeshDomain(ctx)
		if err != nil {
			return fmt.Errorf("lookup mesh domain: %w", err)
		}
	}
	return nil
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
