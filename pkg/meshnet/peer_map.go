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
	AllowedIPs   []string
	LocalRoutes  []netip.Prefix
	Routes       []Route
	Visited      map[types.NodeID]struct{}
	Depth        int
}

// SkipNode reports if the given node ID should be skipped.
func (g *GraphWalk) SkipNode(id types.NodeID) bool {
	// Skip ourselves
	if id == g.SourceNode {
		return true
	}
	// Skip nodes we've already visited
	if _, ok := g.Visited[id]; ok {
		return true
	}
	// Skip direct edges to the source
	directAdjacents := g.AdjacencyMap[g.SourceNode]
	if _, ok := directAdjacents[id]; ok {
		return true
	}
	return false
}

// WalkedPeer is a peer that has been walked. We track routes
// separately so we can do a final iteration to determine the
// smallest depth for each route.
type WalkedPeer struct {
	*v1.WireGuardPeer
	Routes []Route
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
	log := context.LoggerFrom(ctx).With("source-peer", peerID)
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
	directAdjacents := adjacencyMap[peerID]
	peers := make([]WalkedPeer, 0, len(directAdjacents))
	for adjacent, edge := range directAdjacents {
		directPeer, err := graph.Vertex(adjacent)
		if err != nil {
			return nil, fmt.Errorf("get vertex: %w", err)
		}
		if directPeer.PublicKey == "" {
			continue
		}
		_, err = crypto.DecodePublicKey(directPeer.GetPublicKey())
		if err != nil {
			log.Error("Node has invalid public key, ignoring", "node", directPeer.GetId(), "public_key", directPeer.GetPublicKey())
			continue
		}
		// Determine the preferred wireguard endpoint
		// When returning a wireguard peer, we make sure the primary endpoint
		// contains the port of the edge we're traversing.
		var primaryEndpoint string
		if directPeer.PrimaryEndpoint != "" {
			for _, endpoint := range directPeer.GetWireguardEndpoints() {
				if strings.HasPrefix(endpoint, directPeer.PrimaryEndpoint) {
					primaryEndpoint = endpoint
					break
				}
			}
		}
		if primaryEndpoint == "" && len(directPeer.WireguardEndpoints) > 0 {
			primaryEndpoint = directPeer.WireguardEndpoints[0]
		}
		directPeer.MeshNode.PrimaryEndpoint = primaryEndpoint
		peer := WalkedPeer{
			WireGuardPeer: &v1.WireGuardPeer{
				Node:          directPeer.MeshNode,
				Proto:         types.ConnectProtoFromEdgeAttrs(edge.Properties.Attributes),
				AllowedIPs:    []string{},
				AllowedRoutes: []string{},
			},
		}
		var target types.MeshNode
		directPeer.DeepCopyInto(&target)
		walk := GraphWalk{
			Graph:        graph,
			Networking:   nw,
			AdjacencyMap: adjacencyMap,
			SourceNode:   peerID,
			TargetNode:   &target,
			LocalRoutes:  ourRoutes,
			AllowedIPs:   []string{},
			Routes:       []Route{},
			Visited:      map[types.NodeID]struct{}{},
			Depth:        0,
		}
		err = recursePeers(ctx, &walk)
		if err != nil {
			return nil, fmt.Errorf("recurse direct peer: %w", err)
		}
		log.Debug("Walk results for graph edge", "target-peer", directPeer.GetId(), "results", walk)
		peer.Routes = append(peer.Routes, walk.Routes...)
		peer.AllowedIPs = append(peer.AllowedIPs, walk.AllowedIPs...)
		peers = append(peers, peer)
	}
	// Walk our results and assign routes based on shortest path.
	out := make([]*v1.WireGuardPeer, 0, len(peers))
	for _, peer := range peers {
		// For each route, check if its the shortest depth for that prefix.
		for _, route := range peer.Routes {
			if isSmallestDepth(peers, route) {
				// This is the shortest depth for this route.
				peer.AllowedRoutes = append(peer.AllowedRoutes, route.CIDR.String())
				peer.AllowedIPs = append(peer.AllowedIPs, route.CIDR.String())
			}
		}
		out = append(out, peer.WireGuardPeer)
	}
	return out, nil
}

func recursePeers(ctx context.Context, walk *GraphWalk) error {
	if walk.TargetNode.PrivateAddrV4().IsValid() {
		walk.AllowedIPs = append(walk.AllowedIPs, walk.TargetNode.PrivateAddrV4().String())
	}
	if walk.TargetNode.PrivateAddrV6().IsValid() {
		walk.AllowedIPs = append(walk.AllowedIPs, walk.TargetNode.PrivateAddrV6().String())
	}
	// Does this peer expose routes?
	routes, err := walk.Networking.GetRoutesByNode(ctx, walk.TargetNode.NodeID())
	if err != nil {
		return fmt.Errorf("get routes by node: %w", err)
	}
	for _, route := range routes {
		for _, cidr := range route.DestinationPrefixes() {
			if !slices.Contains(walk.AllowedIPs, cidr.String()) && !slices.Contains(walk.LocalRoutes, cidr) {
				if !routeExists(walk.Routes, cidr) {
					walk.Routes = append(walk.Routes, Route{
						CIDR:  cidr,
						Depth: walk.Depth,
					})
				}
			}
		}
	}
	walk.Depth++
	err = recursePeerEdges(ctx, walk)
	if err != nil {
		return fmt.Errorf("recurse peer edges: %w", err)
	}
	return nil
}

func recursePeerEdges(ctx context.Context, walk *GraphWalk) error {
	if walk.Visited == nil {
		walk.Visited = make(map[types.NodeID]struct{})
	}
	walk.Visited[walk.TargetNode.NodeID()] = struct{}{}
	targets := walk.AdjacencyMap[walk.TargetNode.NodeID()]
	for target := range targets {
		if walk.SkipNode(target) {
			continue
		}
		walk.Visited[target] = struct{}{}
		targetNode, err := walk.Graph.Vertex(target)
		if err != nil {
			return fmt.Errorf("get graph vertex: %w", err)
		}
		if targetNode.PublicKey == "" {
			continue
		}
		if targetNode.PrivateAddrV4().IsValid() {
			walk.AllowedIPs = append(walk.AllowedIPs, targetNode.PrivateAddrV4().String())
		}
		if targetNode.PrivateAddrV6().IsValid() {
			walk.AllowedIPs = append(walk.AllowedIPs, targetNode.PrivateAddrV6().String())
		}
		routes, err := walk.Networking.GetRoutesByNode(ctx, targetNode.NodeID())
		if err != nil {
			return fmt.Errorf("get routes by node: %w", err)
		}
		for _, route := range routes {
			for _, cidr := range route.DestinationPrefixes() {
				if !slices.Contains(walk.AllowedIPs, cidr.String()) && !slices.Contains(walk.LocalRoutes, cidr) {
					if !routeExists(walk.Routes, cidr) {
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
		err = recursePeerEdges(ctx, walk)
		if err != nil {
			return fmt.Errorf("recurse vertex edges: %w", err)
		}
	}
	return nil
}

func isSmallestDepth(peers []WalkedPeer, rt Route) bool {
	depth := rt.Depth
	for _, peer := range peers {
		for _, route := range peer.Routes {
			if route.CIDR == rt.CIDR && route.Depth < depth {
				return false
			}
		}
	}
	return true
}

func routeExists(routes []Route, rt netip.Prefix) bool {
	for _, route := range routes {
		if route.CIDR == rt {
			return true
		}
	}
	return false
}
