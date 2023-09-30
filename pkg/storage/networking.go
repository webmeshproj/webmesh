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

package storage

import (
	"net/netip"
	"slices"
	"strings"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

var (
	// BootstrapNodesNetworkACLName is the name of the bootstrap nodes NetworkACL.
	BootstrapNodesNetworkACLName = []byte("bootstrap-nodes")
	// NetworkACLsPrefix is where NetworkACLs are stored in the database.
	NetworkACLsPrefix = types.RegistryPrefix.For([]byte("network-acls"))
	// RoutesPrefix is where Routes are stored in the database.
	RoutesPrefix = types.RegistryPrefix.For([]byte("routes"))
)

// Networking is the interface to the database models for network resources.
type Networking interface {
	// PutNetworkACL creates or updates a NetworkACL.
	PutNetworkACL(ctx context.Context, acl *v1.NetworkACL) error
	// GetNetworkACL returns a NetworkACL by name.
	GetNetworkACL(ctx context.Context, name string) (types.NetworkACL, error)
	// DeleteNetworkACL deletes a NetworkACL by name.
	DeleteNetworkACL(ctx context.Context, name string) error
	// ListNetworkACLs returns a list of NetworkACLs.
	ListNetworkACLs(ctx context.Context) (types.NetworkACLs, error)

	// PutRoute creates or updates a Route.
	PutRoute(ctx context.Context, route *v1.Route) error
	// GetRoute returns a Route by name.
	GetRoute(ctx context.Context, name string) (types.Route, error)
	// GetRoutesByNode returns a list of Routes for a given Node.
	GetRoutesByNode(ctx context.Context, nodeID types.NodeID) (types.Routes, error)
	// GetRoutesByCIDR returns a list of Routes for a given CIDR.
	GetRoutesByCIDR(ctx context.Context, cidr netip.Prefix) (types.Routes, error)
	// DeleteRoute deletes a Route by name.
	DeleteRoute(ctx context.Context, name string) error
	// ListRoutes returns a list of Routes.
	ListRoutes(ctx context.Context) (types.Routes, error)

	// FilterGraph filters the adjacency map in the given graph for the given node ID according
	// to the current network ACLs. If the ACL list is nil, an empty adjacency map is returned. An
	// error is returned on faiure building the initial map or any database error.
	FilterGraph(ctx context.Context, graph types.PeerGraph, nodeID types.NodeID) (types.AdjacencyMap, error)
}

// ExpandACLs will use the given RBAC interface to expand any group references
// in the ACLs.
func ExpandACLs(ctx context.Context, rbac RBAC, acls types.NetworkACLs) error {
	for _, acl := range acls {
		if err := ExpandACL(ctx, rbac, acl); err != nil {
			return err
		}
	}
	return nil
}

// ExpandACL will use the given RBAC interface to expand any group references
// in the ACL.
func ExpandACL(ctx context.Context, rbac RBAC, acl types.NetworkACL) error {
	// Expand group references in the source nodes
	var srcNodes []string
	for _, node := range acl.GetSourceNodes() {
		if !strings.HasPrefix(node, types.GroupReference) {
			srcNodes = append(srcNodes, node)
			continue
		}
		groupName := strings.TrimPrefix(node, types.GroupReference)
		context.LoggerFrom(ctx).Debug("Expanding group reference", "group", groupName)
		group, err := rbac.GetGroup(ctx, groupName)
		if err != nil {
			if !errors.Is(err, errors.ErrGroupNotFound) {
				context.LoggerFrom(ctx).Error("Failed to lookup group", "group", groupName, "error", err.Error())
				return err
			}
			// If the group doesn't exist, we'll just ignore it.
			continue
		}
		for _, subject := range group.GetSubjects() {
			if !slices.Contains(srcNodes, subject.GetName()) {
				srcNodes = append(srcNodes, subject.GetName())
			}
		}
	}
	acl.SourceNodes = srcNodes
	// The same for destination nodes
	var dstNodes []string
	for _, node := range acl.GetDestinationNodes() {
		if !strings.HasPrefix(node, types.GroupReference) {
			dstNodes = append(dstNodes, node)
			continue
		}
		groupName := strings.TrimPrefix(node, types.GroupReference)
		context.LoggerFrom(ctx).Debug("Expanding group reference", "group", groupName)
		group, err := rbac.GetGroup(ctx, groupName)
		if err != nil {
			if !errors.IsGroupNotFound(err) {
				context.LoggerFrom(ctx).Error("Failed to lookup group", "group", groupName, "error", err.Error())
				return err
			}
			// If the group doesn't exist, we'll just ignore it.
			continue
		}
		for _, subject := range group.GetSubjects() {
			if !slices.Contains(dstNodes, subject.GetName()) {
				dstNodes = append(dstNodes, subject.GetName())
			}
		}
	}
	acl.DestinationNodes = dstNodes
	return nil
}
