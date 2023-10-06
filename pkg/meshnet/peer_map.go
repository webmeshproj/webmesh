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

package meshnet

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb/networking"
	"github.com/webmeshproj/webmesh/pkg/storage/storageutil"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// GraphWalk is the structure used to recursively walk the graph
// and build the adjacency map.
type GraphWalk struct {
	Graph        types.PeerGraph
	Networking   networking.Networking
	AdjacencyMap types.AdjacencyMap
	SourceNode   types.NodeID
	TargetNode   *types.MeshNode
	AllowedIPs   []netip.Prefix
	LocalRoutes  []netip.Prefix
	Routes       []Route
	Visited      map[types.NodeID]struct{}
	Depth        int
}

// Route tracks a route and the depth into the graph of the route.
// Smallest depth wins in the end.
type Route struct {
	CIDR  netip.Prefix
	Depth int
}

// WireGuardPeersFor returns the WireGuard peers for the given peer ID.
// Peers are filtered by network ACLs.
func WireGuardPeersFor(ctx context.Context, st storage.MeshDB, peerID types.NodeID) ([]*v1.WireGuardPeer, error) {
	graph := st.Peers().Graph()
	nw := st.Networking()
	adjacencyMap, err := FilterGraph(ctx, st, peerID)
	if err != nil {
		return nil, fmt.Errorf("filter adjacency map: %w", err)
	}
	routes, err := nw.GetRoutesByNode(ctx, peerID)
	if err != nil {
		return nil, fmt.Errorf("get routes by node: %w", err)
	}
	ourRoutes := make([]netip.Prefix, 0)
	for _, route := range routes {
		ourRoutes = append(ourRoutes, route.DestinationPrefixes()...)
	}
	directAdjacents := adjacencyMap[types.NodeID(peerID)]
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
		peer := &v1.WireGuardPeer{
			Node:          node.MeshNode,
			Proto:         storageutil.ConnectProtoFromEdgeAttrs(edge.Properties.Attributes),
			AllowedIPs:    []string{},
			AllowedRoutes: []string{},
		}
		walk := GraphWalk{
			Graph:        graph,
			Networking:   nw,
			AdjacencyMap: adjacencyMap,
			SourceNode:   peerID,
			TargetNode:   &node,
			LocalRoutes:  ourRoutes,
			Depth:        0,
		}
		err = recursePeers(ctx, &walk)
		if err != nil {
			return nil, fmt.Errorf("recurse allowed IPs: %w", err)
		}
		for _, ip := range walk.AllowedIPs {
			peer.AllowedIPs = append(peer.AllowedIPs, ip.String())
		}
		for _, route := range walk.Routes {
			peer.AllowedRoutes = append(peer.AllowedRoutes, route.CIDR.String())
		}
		out = append(out, peer)
	}
	return out, nil
}

func recursePeers(ctx context.Context, walk *GraphWalk) error {
	if walk.TargetNode.PrivateAddrV4().IsValid() {
		walk.AllowedIPs = append(walk.AllowedIPs, walk.TargetNode.PrivateAddrV4())
	}
	if walk.TargetNode.PrivateAddrV6().IsValid() {
		walk.AllowedIPs = append(walk.AllowedIPs, walk.TargetNode.PrivateAddrV6())
	}
	// Does this peer expose routes?
	routes, err := walk.Networking.GetRoutesByNode(ctx, walk.TargetNode.NodeID())
	if err != nil {
		return fmt.Errorf("get routes by node: %w", err)
	}
	if len(routes) > 0 {
		for _, route := range routes {
			for _, cidr := range route.DestinationPrefixes() {
				if !slices.Contains(walk.AllowedIPs, cidr) && !slices.Contains(walk.LocalRoutes, cidr) {
					walk.Routes = append(walk.Routes, Route{
						CIDR:  cidr,
						Depth: walk.Depth,
					})
				}
			}
		}
	}
	err = recurseEdges(ctx, walk)
	if err != nil {
		return fmt.Errorf("recurse edge allowed IPs: %w", err)
	}
	return nil
}

func recurseEdges(ctx context.Context, walk *GraphWalk) (err error) {
	if walk.Visited == nil {
		walk.Visited = make(map[types.NodeID]struct{})
	}
	directAdjacents := walk.AdjacencyMap[walk.SourceNode]
	walk.Visited[walk.TargetNode.NodeID()] = struct{}{}
	targets := walk.AdjacencyMap[walk.TargetNode.NodeID()]
	for target := range targets {
		// Skip ourselves
		if target == walk.SourceNode {
			continue
		}
		// Skip direct edges to the source
		if _, ok := directAdjacents[target]; ok {
			continue
		}
		// Skip nodes we've already visited
		if _, ok := walk.Visited[target]; ok {
			continue
		}
		walk.Visited[target] = struct{}{}
		targetNode, err := walk.Graph.Vertex(target)
		if err != nil {
			return fmt.Errorf("get vertex: %w", err)
		}
		if targetNode.PublicKey == "" {
			continue
		}
		if targetNode.PrivateAddrV4().IsValid() {
			walk.AllowedIPs = append(walk.AllowedIPs, targetNode.PrivateAddrV4())
		}
		if targetNode.PrivateAddrV6().IsValid() {
			walk.AllowedIPs = append(walk.AllowedIPs, targetNode.PrivateAddrV6())
		}
		routes, err := walk.Networking.GetRoutesByNode(ctx, targetNode.NodeID())
		if err != nil {
			return fmt.Errorf("get routes by node: %w", err)
		}
		if len(routes) > 0 {
			for _, route := range routes {
				for _, cidr := range route.DestinationPrefixes() {
					if !slices.Contains(walk.AllowedIPs, cidr) && !slices.Contains(walk.LocalRoutes, cidr) {
						walk.Routes = append(walk.Routes, Route{
							CIDR:  cidr,
							Depth: walk.Depth,
						})
					}
				}
			}
		}
		walk.Depth++
		walk.TargetNode = &targetNode
		err = recurseEdges(ctx, walk)
		if err != nil {
			return fmt.Errorf("recurse allowed IPs: %w", err)
		}
	}
	return
}
