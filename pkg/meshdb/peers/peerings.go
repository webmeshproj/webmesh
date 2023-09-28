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

// Package meshutil contains helpers for computing networking information from the mesh.
package peers

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	peergraph "github.com/webmeshproj/webmesh/pkg/meshdb/graph"
	"github.com/webmeshproj/webmesh/pkg/meshdb/networking"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/storageutil"
)

// WireGuardPeersFor returns the WireGuard peers for the given peer ID.
// Peers are filtered by network ACLs.
func WireGuardPeersFor(ctx context.Context, st storage.MeshStorage, peerID string) ([]*v1.WireGuardPeer, error) {
	peers := New(st)
	graph := peers.Graph()
	nw := networking.New(st)
	adjacencyMap, err := nw.FilterGraph(ctx, peers.Graph(), peerID)
	if err != nil {
		return nil, fmt.Errorf("filter adjacency map: %w", err)
	}
	routes, err := nw.GetRoutesByNode(ctx, peerID)
	if err != nil {
		return nil, fmt.Errorf("get routes by node: %w", err)
	}
	ourRoutes := make([]netip.Prefix, 0)
	for _, route := range routes {
		for _, cidr := range route.GetDestinationCidrs() {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return nil, fmt.Errorf("parse prefix %q: %w", cidr, err)
			}
			ourRoutes = append(ourRoutes, prefix)
		}
	}
	directAdjacents := adjacencyMap[peergraph.NodeID(peerID)]
	out := make([]*v1.WireGuardPeer, 0, len(directAdjacents))
	for adjacent, edge := range directAdjacents {
		node, err := graph.Vertex(adjacent)
		if err != nil {
			return nil, fmt.Errorf("get vertex: %w", err)
		}
		if node.PublicKey == "" {
			continue
		}
		_, err = crypto.DecodePublicKey(node.PublicKey)
		if err != nil {
			context.LoggerFrom(ctx).Error("Node has invalid public key, ignoring", "node", node.Id, "public_key", node.PublicKey)
			continue
		}
		// Determine the preferred wireguard endpoint
		// When returning a wireguard peer, we make sure the primary endpoint
		// contains the port of the edge we're traversing.
		var primaryEndpoint string
		if node.PrimaryEndpoint != "" {
			for _, endpoint := range node.GetWireguardEndpoints() {
				if strings.HasPrefix(endpoint, node.PrimaryEndpoint) {
					primaryEndpoint = endpoint
					break
				}
			}
		}
		if primaryEndpoint == "" && len(node.WireguardEndpoints) > 0 {
			primaryEndpoint = node.WireguardEndpoints[0]
		}
		node.MeshNode.PrimaryEndpoint = primaryEndpoint
		// Each direct adjacent is a peer
		peer := &v1.WireGuardPeer{
			Node:          node.MeshNode,
			Proto:         storageutil.ConnectProtoFromEdgeAttrs(edge.Properties.Attributes),
			AllowedIps:    []string{},
			AllowedRoutes: []string{},
		}
		allowedIPs, allowedRoutes, err := recursePeers(ctx, nw, graph, adjacencyMap, peerID, ourRoutes, &node)
		if err != nil {
			return nil, fmt.Errorf("recurse allowed IPs: %w", err)
		}
		var ourAllowedIPs []string
		for _, ip := range allowedIPs {
			ourAllowedIPs = append(ourAllowedIPs, ip.String())
		}
		var ourAllowedRoutes []string
		for _, route := range allowedRoutes {
			ourAllowedRoutes = append(ourAllowedRoutes, route.String())
		}
		peer.AllowedIps = ourAllowedIPs
		peer.AllowedRoutes = ourAllowedRoutes
		out = append(out, peer)
	}
	return out, nil
}

func recursePeers(
	ctx context.Context,
	nw networking.Networking,
	graph peergraph.Graph,
	adjacencyMap peergraph.AdjacencyMap,
	thisPeer string,
	thisRoutes []netip.Prefix,
	node *peergraph.MeshNode,
) (allowedIPs, allowedRoutes []netip.Prefix, err error) {
	if node.PrivateAddrV4().IsValid() {
		allowedIPs = append(allowedIPs, node.PrivateAddrV4())
	}
	if node.PrivateAddrV6().IsValid() {
		allowedIPs = append(allowedIPs, node.PrivateAddrV6())
	}
	// Does this peer expose routes?
	routes, err := nw.GetRoutesByNode(ctx, node.GetId())
	if err != nil {
		return nil, nil, fmt.Errorf("get routes by node: %w", err)
	}
	if len(routes) > 0 {
		for _, route := range routes {
			for _, cidr := range route.GetDestinationCidrs() {
				prefix, err := netip.ParsePrefix(cidr)
				if err != nil {
					return nil, nil, fmt.Errorf("parse prefix: %w", err)
				}
				if !slices.Contains(allowedIPs, prefix) && !slices.Contains(thisRoutes, prefix) {
					allowedIPs = append(allowedIPs, prefix)
				}
			}
		}
	}
	edgeIPs, edgeRoutes, err := recurseEdges(ctx, nw, graph, adjacencyMap, thisPeer, thisRoutes, node, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("recurse edge allowed IPs: %w", err)
	}
	for _, ip := range edgeIPs {
		if !slices.Contains(allowedIPs, ip) {
			allowedIPs = append(allowedIPs, ip)
		}
	}
	for _, route := range edgeRoutes {
		if !slices.Contains(allowedRoutes, route) {
			allowedRoutes = append(allowedRoutes, route)
		}
	}
	return
}

func recurseEdges(
	ctx context.Context,
	nw networking.Networking,
	graph peergraph.Graph,
	adjacencyMap peergraph.AdjacencyMap,
	thisPeer string,
	thisRoutes []netip.Prefix,
	node *peergraph.MeshNode,
	visited map[peergraph.NodeID]struct{},
) (allowedIPs, allowedRoutes []netip.Prefix, err error) {
	if visited == nil {
		visited = make(map[peergraph.NodeID]struct{})
	}
	directAdjacents := adjacencyMap[peergraph.NodeID(thisPeer)]
	visited[peergraph.NodeID(node.GetId())] = struct{}{}
	targets := adjacencyMap[peergraph.NodeID(node.GetId())]
	for target := range targets {
		if target.String() == thisPeer {
			continue
		}
		if _, ok := directAdjacents[target]; ok {
			continue
		}
		if _, ok := visited[target]; ok {
			continue
		}
		visited[target] = struct{}{}
		targetNode, err := graph.Vertex(target)
		if err != nil {
			return nil, nil, fmt.Errorf("get vertex: %w", err)
		}
		if targetNode.PublicKey == "" {
			continue
		}
		if targetNode.PrivateAddrV4().IsValid() {
			allowedIPs = append(allowedIPs, targetNode.PrivateAddrV4())
		}
		if targetNode.PrivateAddrV6().IsValid() {
			allowedIPs = append(allowedIPs, targetNode.PrivateAddrV6())
		}
		// Does this peer expose routes?
		routes, err := nw.GetRoutesByNode(ctx, targetNode.GetId())
		if err != nil {
			return nil, nil, fmt.Errorf("get routes by node: %w", err)
		}
		if len(routes) > 0 {
			for _, route := range routes {
				for _, cidr := range route.GetDestinationCidrs() {
					prefix, err := netip.ParsePrefix(cidr)
					if err != nil {
						return nil, nil, fmt.Errorf("parse prefix: %w", err)
					}
					if !slices.Contains(allowedIPs, prefix) && !slices.Contains(thisRoutes, prefix) {
						allowedIPs = append(allowedIPs, prefix)
					}
				}
			}
		}
		ips, ipRoutes, err := recurseEdges(ctx, nw, graph, adjacencyMap, thisPeer, thisRoutes, &targetNode, visited)
		if err != nil {
			return nil, nil, fmt.Errorf("recurse allowed IPs: %w", err)
		}
		for _, ip := range ips {
			if !slices.Contains(allowedIPs, ip) {
				allowedIPs = append(allowedIPs, ip)
			}
		}
		for _, ipRoute := range ipRoutes {
			if !slices.Contains(allowedRoutes, ipRoute) {
				allowedRoutes = append(allowedRoutes, ipRoute)
			}
		}
	}
	return
}
