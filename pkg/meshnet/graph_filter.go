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

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// FilterGraph filters the adjacency map in the given graph for the given node name according
// to the current network ACLs. If the ACL list is nil, an empty adjacency map is returned. An
// error is returned on faiure building the initial map or any database error. This implementation
// needs improvement to be more efficient and to allow edges so long as one of the routes encountered is
// allowed. Currently if a single route provided by a destination node is not allowed, the entire node
// is filtered out.
func FilterGraph(ctx context.Context, db storage.MeshDB, thisNodeID types.NodeID) (types.AdjacencyMap, error) {
	log := context.LoggerFrom(ctx)
	graph := db.Peers().Graph()

	// Resolve the current node ID
	thisNode, err := graph.Vertex(thisNodeID)
	if err != nil {
		return nil, fmt.Errorf("get node: %w", err)
	}

	// Gather all the ACLs and the current adjacency map
	acls, err := db.Networking().ListNetworkACLs(ctx)
	if err != nil {
		return nil, fmt.Errorf("list network acls: %w", err)
	}
	if len(acls) == 0 {
		return nil, nil
	}
	err = storage.ExpandACLs(ctx, db.RBAC(), acls)
	if err != nil {
		return nil, fmt.Errorf("expand network acls: %w", err)
	}
	acls.Sort(types.SortDescending)
	fullMap, err := types.NewAdjacencyMap(graph)
	if err != nil {
		return nil, fmt.Errorf("build adjacency map: %w", err)
	}
	log.Debug("Full adjacency map", "from", thisNode.Id, "map", fullMap)

	// Start with a copy of the full map and filter out nodes that are not allowed to communicate
	// with the current node.
	filtered := make(types.AdjacencyMap)
	filtered[thisNode.NodeID()] = fullMap[thisNode.NodeID()]

Nodes:
	for nodeID := range fullMap {
		if nodeID.String() == thisNode.GetId() {
			continue
		}
		node, err := graph.Vertex(nodeID)
		if err != nil {
			return nil, fmt.Errorf("get node: %w", err)
		}
		if !acls.AllowNodesToCommunicate(ctx, thisNode, node) {
			log.Debug("Nodes not allowed to communicate", "nodeA", thisNode, "nodeB", node)
			delete(filtered[thisNode.NodeID()], node.NodeID())
			continue Nodes
		}
		// If the destination node exposes additional routes, check if the nodes can communicate
		// via any of those routes.
		routes, err := db.Networking().GetRoutesByNode(ctx, node.NodeID())
		if err != nil {
			return nil, fmt.Errorf("get routes by node: %w", err)
		}
		for _, route := range routes {
			for _, cidr := range route.DestinationPrefixes() {
				var action types.NetworkAction
				if cidr.Addr().Is4() {
					action = types.NetworkAction{
						NetworkAction: &v1.NetworkAction{
							SrcNode: thisNode.GetId(),
							SrcCIDR: thisNode.GetPrivateIPv4(),
							DstNode: node.GetId(),
							DstCIDR: cidr.String(),
						},
					}
				} else {
					action = types.NetworkAction{
						NetworkAction: &v1.NetworkAction{
							SrcNode: thisNode.GetId(),
							SrcCIDR: thisNode.GetPrivateIPv6(),
							DstNode: node.GetId(),
							DstCIDR: cidr.String(),
						},
					}
				}
				if !acls.Accept(ctx, action) {
					log.Debug("filtering node", "node", node, "reason", "route not allowed", "action", action)
					delete(filtered[thisNode.NodeID()], node.NodeID())
					continue Nodes
				}
			}
		}
		filtered[node.NodeID()] = make(types.EdgeMap)
	}
	for node := range filtered {
		edges, ok := fullMap[node]
		if !ok {
			continue
		}
	Peers:
		for peerID, edge := range edges {
			e := edge
			if peerID.String() == thisNode.GetId() {
				filtered[node][peerID] = e
				continue
			}
			peer, err := graph.Vertex(peerID)
			if err != nil {
				return nil, fmt.Errorf("get peer: %w", err)
			}
			if !acls.AllowNodesToCommunicate(ctx, thisNode, peer) {
				log.Debug("Nodes not allowed to communicate", "nodeA", thisNode, "nodeB", peer)
				continue Peers
			}
			// If the peer exposes additional routes, check if the nodes can communicate
			// via any of those routes.
			routes, err := db.Networking().GetRoutesByNode(ctx, peerID)
			if err != nil {
				return nil, fmt.Errorf("get routes by node: %w", err)
			}
			for _, route := range routes {
				for _, cidr := range route.DestinationPrefixes() {
					var action v1.NetworkAction
					if cidr.Addr().Is4() {
						action = v1.NetworkAction{
							SrcNode: thisNode.GetId(),
							SrcCIDR: thisNode.GetPrivateIPv4(),
							DstNode: peerID.String(),
							DstCIDR: cidr.String(),
						}
					} else {
						action = v1.NetworkAction{
							SrcNode: thisNode.GetId(),
							SrcCIDR: thisNode.GetPrivateIPv6(),
							DstNode: peerID.String(),
							DstCIDR: cidr.String(),
						}
					}
					if !acls.Accept(ctx, types.NetworkAction{NetworkAction: &action}) {
						log.Debug("filtering peer", "peer", peer, "reason", "route not allowed", "action", &action)
						continue Peers
					}
				}
			}
			filtered[node][peerID] = e
		}
	}

	log.Debug("Filtered adjacency map", "from", thisNode.Id, "map", filtered)
	return filtered, nil
}
