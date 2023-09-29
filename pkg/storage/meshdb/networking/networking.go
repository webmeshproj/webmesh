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

// Package networking contains interfaces to the database models for Network ACLs and Routes.
package networking

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

var (
	// BootstrapNodesNetworkACLName is the name of the bootstrap nodes NetworkACL.
	BootstrapNodesNetworkACLName = []byte("bootstrap-nodes")
	// NetworkACLsPrefix is where NetworkACLs are stored in the database.
	NetworkACLsPrefix = storage.RegistryPrefix.For([]byte("network-acls"))
	// RoutesPrefix is where Routes are stored in the database.
	RoutesPrefix = storage.RegistryPrefix.For([]byte("routes"))
	// GroupReference is the prefix of a node name that indicates it is a group reference.
	GroupReference = "group:"
)

// ErrACLNotFound is returned when a NetworkACL is not found.
var ErrACLNotFound = errors.New("network acl not found")

// ErrRouteNotFound is returned when a Route is not found.
var ErrRouteNotFound = errors.New("route not found")

// ErrInvalidACL is returned when a NetworkACL is invalid.
var ErrInvalidACL = errors.New("invalid network acl")

// ErrInvalidRoute is returned when a Route is invalid.
var ErrInvalidRoute = errors.New("invalid route")

// Networking is the interface to the database models for network resources.
type Networking interface {
	// PutNetworkACL creates or updates a NetworkACL.
	PutNetworkACL(ctx context.Context, acl *v1.NetworkACL) error
	// GetNetworkACL returns a NetworkACL by name.
	GetNetworkACL(ctx context.Context, name string) (ACL, error)
	// DeleteNetworkACL deletes a NetworkACL by name.
	DeleteNetworkACL(ctx context.Context, name string) error
	// ListNetworkACLs returns a list of NetworkACLs.
	ListNetworkACLs(ctx context.Context) (ACLs, error)

	// PutRoute creates or updates a Route.
	PutRoute(ctx context.Context, route *v1.Route) error
	// GetRoute returns a Route by name.
	GetRoute(ctx context.Context, name string) (types.Route, error)
	// GetRoutesByNode returns a list of Routes for a given Node.
	GetRoutesByNode(ctx context.Context, nodeName string) (types.Routes, error)
	// GetRoutesByCIDR returns a list of Routes for a given CIDR.
	GetRoutesByCIDR(ctx context.Context, cidr netip.Prefix) (types.Routes, error)
	// DeleteRoute deletes a Route by name.
	DeleteRoute(ctx context.Context, name string) error
	// ListRoutes returns a list of Routes.
	ListRoutes(ctx context.Context) (types.Routes, error)

	// FilterGraph filters the adjacency map in the given graph for the given node ID according
	// to the current network ACLs. If the ACL list is nil, an empty adjacency map is returned. An
	// error is returned on faiure building the initial map or any database error.
	FilterGraph(ctx context.Context, graph types.PeerGraph, nodeID string) (types.AdjacencyMap, error)
}

// New returns a new Networking interface.
func New(st storage.MeshStorage) Networking {
	return &networking{st}
}

type networking struct {
	storage.MeshStorage
}

// PutNetworkACL creates or updates a NetworkACL.
func (n *networking) PutNetworkACL(ctx context.Context, acl *v1.NetworkACL) error {
	err := ValidateACL(acl)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidACL, err)
	}
	key := NetworkACLsPrefix.For([]byte(acl.GetName()))
	data, err := (ACL{NetworkACL: acl}).MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal network acl: %w", err)
	}
	err = n.PutValue(ctx, key, data, 0)
	if err != nil {
		return fmt.Errorf("put network acl: %w", err)
	}
	return nil
}

// GetNetworkACL returns a NetworkACL by name.
func (n *networking) GetNetworkACL(ctx context.Context, name string) (ACL, error) {
	key := NetworkACLsPrefix.For([]byte(name))
	data, err := n.GetValue(ctx, key)
	if err != nil {
		if errors.Is(err, storage.ErrKeyNotFound) {
			return ACL{}, ErrACLNotFound
		}
		return ACL{}, fmt.Errorf("get network acl: %w", err)
	}
	var acl ACL
	err = acl.UnmarshalJSON(data)
	if err != nil {
		return ACL{}, fmt.Errorf("unmarshal network acl: %w", err)
	}
	acl.storage = n.MeshStorage
	return acl, nil
}

// DeleteNetworkACL deletes a NetworkACL by name.
func (n *networking) DeleteNetworkACL(ctx context.Context, name string) error {
	key := NetworkACLsPrefix.For([]byte(name))
	err := n.Delete(ctx, key)
	if err != nil && !errors.Is(err, storage.ErrKeyNotFound) {
		return fmt.Errorf("delete network acl: %w", err)
	}
	return nil
}

// ListNetworkACLs returns a list of NetworkACLs.
func (n *networking) ListNetworkACLs(ctx context.Context) (ACLs, error) {
	out := make(ACLs, 0)
	err := n.IterPrefix(ctx, NetworkACLsPrefix, func(key, value []byte) error {
		if bytes.Equal(key, NetworkACLsPrefix) {
			return nil
		}
		var acl ACL
		err := acl.UnmarshalJSON(value)
		if err != nil {
			return fmt.Errorf("unmarshal network acl: %w", err)
		}
		acl.storage = n.MeshStorage
		out = append(out, &acl)
		return nil
	})
	return out, err
}

// PutRoute creates or updates a Route.
func (n *networking) PutRoute(ctx context.Context, route *v1.Route) error {
	err := types.ValidateRoute(route)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidRoute, err)
	}
	key := RoutesPrefix.For([]byte(route.GetName()))
	data, err := (types.Route{Route: route}).MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal route: %w", err)
	}
	err = n.PutValue(ctx, key, data, 0)
	if err != nil {
		return fmt.Errorf("put network route: %w", err)
	}
	return nil
}

// GetRoute returns a Route by name.
func (n *networking) GetRoute(ctx context.Context, name string) (types.Route, error) {
	key := RoutesPrefix.For([]byte(name))
	data, err := n.GetValue(ctx, key)
	if err != nil {
		if errors.Is(err, storage.ErrKeyNotFound) {
			return types.Route{}, ErrRouteNotFound
		}
		return types.Route{}, fmt.Errorf("get network route: %w", err)
	}
	var rt types.Route
	err = rt.UnmarshalJSON(data)
	if err != nil {
		return types.Route{}, fmt.Errorf("unmarshal network route: %w", err)
	}
	return rt, nil
}

// GetRoutesByNode returns a list of Routes for a given Node.
func (n *networking) GetRoutesByNode(ctx context.Context, nodeName string) (types.Routes, error) {
	routes, err := n.ListRoutes(ctx)
	if err != nil {
		return nil, fmt.Errorf("list network routes: %w", err)
	}
	out := make([]types.Route, 0)
	for _, route := range routes {
		r := route
		if r.GetNode() == nodeName {
			out = append(out, r)
		}
	}
	return out, nil
}

// GetRoutesByCIDR returns a list of Routes for a given CIDR.
func (n *networking) GetRoutesByCIDR(ctx context.Context, cidr netip.Prefix) (types.Routes, error) {
	routes, err := n.ListRoutes(ctx)
	if err != nil {
		return nil, fmt.Errorf("list network routes: %w", err)
	}
	out := make([]types.Route, 0)
	for _, route := range routes {
		r := route
		for _, destination := range r.DestinationPrefixes() {
			if destination.Bits() != cidr.Bits() {
				continue
			}
			if destination.Addr().Compare(cidr.Addr()) != 0 {
				continue
			}
			out = append(out, r)
		}
	}
	return out, nil
}

// DeleteRoute deletes a Route by name.
func (n *networking) DeleteRoute(ctx context.Context, name string) error {
	key := RoutesPrefix.For([]byte(name))
	err := n.Delete(ctx, key)
	if err != nil && !errors.Is(err, storage.ErrKeyNotFound) {
		return fmt.Errorf("delete network route: %w", err)
	}
	return nil
}

// ListRoutes returns a list of Routes.
func (n *networking) ListRoutes(ctx context.Context) (types.Routes, error) {
	out := make([]types.Route, 0)
	err := n.IterPrefix(ctx, RoutesPrefix, func(key, value []byte) error {
		if bytes.Equal(key, RoutesPrefix) {
			return nil
		}
		var rt types.Route
		err := rt.UnmarshalJSON(value)
		if err != nil {
			return fmt.Errorf("unmarshal network route: %w", err)
		}
		out = append(out, rt)
		return nil
	})
	return out, err
}

// FilterGraph filters the adjacency map in the given graph for the given node name according
// to the current network ACLs. If the ACL list is nil, an empty adjacency map is returned. An
// error is returned on faiure building the initial map or any database error. This implementation
// needs improvement to be more efficient and to allow edges so long as one of the routes encountered is
// allowed. Currently if a single route provided by a destination node is not allowed, the entire node
// is filtered out.
func (n *networking) FilterGraph(ctx context.Context, graph types.PeerGraph, thisNodeID string) (types.AdjacencyMap, error) {
	log := context.LoggerFrom(ctx)

	// Resolve the current node ID
	thisNode, err := graph.Vertex(types.NodeID(thisNodeID))
	if err != nil {
		return nil, fmt.Errorf("get node: %w", err)
	}

	// Gather all the ACLs and the current adjacency map
	acls, err := n.ListNetworkACLs(ctx)
	if err != nil {
		return nil, fmt.Errorf("list network acls: %w", err)
	}
	if len(acls) == 0 {
		return nil, nil
	}
	err = acls.Expand(ctx)
	if err != nil {
		return nil, fmt.Errorf("expand network acls: %w", err)
	}
	acls.Sort(SortDescending)
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
		routes, err := n.GetRoutesByNode(ctx, node.GetId())
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
							SrcCidr: thisNode.GetPrivateIpv4(),
							DstNode: node.GetId(),
							DstCidr: cidr.String(),
						},
					}
				} else {
					action = types.NetworkAction{
						NetworkAction: &v1.NetworkAction{
							SrcNode: thisNode.GetId(),
							SrcCidr: thisNode.GetPrivateIpv6(),
							DstNode: node.GetId(),
							DstCidr: cidr.String(),
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
			routes, err := n.GetRoutesByNode(ctx, peerID.String())
			if err != nil {
				return nil, fmt.Errorf("get routes by node: %w", err)
			}
			for _, route := range routes {
				for _, cidr := range route.DestinationPrefixes() {
					var action v1.NetworkAction
					if cidr.Addr().Is4() {
						action = v1.NetworkAction{
							SrcNode: thisNode.GetId(),
							SrcCidr: thisNode.GetPrivateIpv4(),
							DstNode: peerID.String(),
							DstCidr: cidr.String(),
						}
					} else {
						action = v1.NetworkAction{
							SrcNode: thisNode.GetId(),
							SrcCidr: thisNode.GetPrivateIpv6(),
							DstNode: peerID.String(),
							DstCidr: cidr.String(),
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

func toPrefixes(ss []string) []netip.Prefix {
	var out []netip.Prefix
	for _, cidr := range ss {
		var prefix netip.Prefix
		var err error
		if cidr == "*" {
			out = append(out, netip.MustParsePrefix("0.0.0.0/0"))
			out = append(out, netip.MustParsePrefix("::/0"))
			continue
		}
		prefix, err = netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		out = append(out, prefix)
	}
	return out
}
