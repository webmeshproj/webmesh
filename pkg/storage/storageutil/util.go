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

// Package storageutil contains utility functions for mesh database interactions.
package storageutil

import (
	"context"
	"fmt"

	"github.com/dominikbraun/graph"
	v1 "github.com/webmeshproj/api/go/v1"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

var (
	// ErrInvalidQuery is returned when a query is invalid.
	ErrInvalidQuery = fmt.Errorf("invalid query")
	// ErrInvalidArgument is returned when an argument is invalid.
	ErrInvalidArgument = fmt.Errorf("invalid argument")
)

// ServeStorageQuery serves a storage query given a database and a query request.
func ServeStorageQuery(ctx context.Context, db storage.Provider, req *v1.QueryRequest) (*v1.QueryResponse, error) {
	// Parse the request
	query, err := types.ParseStorageQuery(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidQuery, err)
	}
	switch req.GetCommand() {
	case v1.QueryRequest_GET:
		return doGetQuery(ctx, db, query), nil
	case v1.QueryRequest_LIST:
		return doListQuery(ctx, db, query), nil
	case v1.QueryRequest_PUT:
		return doPutQuery(ctx, db, query), nil
	case v1.QueryRequest_DELETE:
		return doDeleteQuery(ctx, db, query), nil
	default:
		return nil, fmt.Errorf("%w: unknown query command %s", ErrInvalidQuery, req.GetCommand().String())
	}
}

func doGetQuery(ctx context.Context, db storage.Provider, req types.StorageQuery) (res *v1.QueryResponse) {
	res = &v1.QueryResponse{}
	var err error
	switch req.GetType() {
	case v1.QueryRequest_VALUE:
		// Legacy requests need to be handled here.
		id, ok := req.Filters().GetID()
		if !ok {
			err = fmt.Errorf("%w: missing id", ErrInvalidArgument)
			res.Error = err.Error()
			return
		}
		var val []byte
		val, err = db.MeshStorage().GetValue(ctx, []byte(id))
		if err != nil {
			res.Error = err.Error()
			return
		}
		res.Items = append(res.Items, val)

	case v1.QueryRequest_PEERS:
		var peer types.MeshNode
		var out []byte
		id, ok := req.Filters().GetID()
		if !ok {
			// We can also get by public key.
			if pubkey, ok := req.Filters().GetPubKey(); ok {
				var decoded crypto.PublicKey
				decoded, err = crypto.DecodePublicKey(pubkey)
				if err != nil {
					err = fmt.Errorf("%w: invalid public key", ErrInvalidArgument)
					res.Error = err.Error()
					return
				}
				peer, err = db.MeshDB().Peers().GetByPubKey(ctx, decoded)
				if err != nil {
					res.Error = err.Error()
					return
				}
				out, err = peer.MarshalProtoJSON()
				if err != nil {
					err = fmt.Errorf("failed to marshal peer: %w", err)
					res.Error = err.Error()
					return
				}
				res.Items = append(res.Items, out)
			}
		} else {
			peer, err = db.MeshDB().Peers().Get(ctx, types.NodeID(id))
			if err != nil {
				res.Error = err.Error()
				return
			}
			out, err = peer.MarshalProtoJSON()
			if err != nil {
				err = fmt.Errorf("failed to marshal peer: %w", err)
				res.Error = err.Error()
				return
			}
			res.Items = append(res.Items, out)
		}

	case v1.QueryRequest_EDGES:
		source, ok := req.Filters().GetSourceNodeID()
		if !ok {
			err = fmt.Errorf("%w: missing source id", ErrInvalidArgument)
			res.Error = err.Error()
			return
		}
		target, ok := req.Filters().GetTargetNodeID()
		if !ok {
			err = fmt.Errorf("%w: missing target id", ErrInvalidArgument)
			res.Error = err.Error()
			return
		}
		var edge types.MeshEdge
		edge, err = db.MeshDB().Peers().GetEdge(ctx, source, target)
		if err != nil {
			res.Error = err.Error()
			return
		}
		var out []byte
		out, err = edge.MarshalProtoJSON()
		if err != nil {
			err = fmt.Errorf("failed to marshal edge: %w", err)
			res.Error = err.Error()
			return
		}
		res.Items = append(res.Items, out)

	case v1.QueryRequest_ROUTES:
		id, ok := req.Filters().GetID()
		if !ok {
			err = fmt.Errorf("%w: missing id", ErrInvalidArgument)
			res.Error = err.Error()
			return
		}
		var route types.Route
		var out []byte
		route, err = db.MeshDB().Networking().GetRoute(ctx, id)
		if err != nil {
			res.Error = err.Error()
			return
		}
		out, err = route.MarshalProtoJSON()
		if err != nil {
			err = fmt.Errorf("failed to marshal route: %w", err)
			res.Error = err.Error()
			return
		}
		res.Items = append(res.Items, out)

	case v1.QueryRequest_ACLS:
		id, ok := req.Filters().GetID()
		if !ok {
			err = fmt.Errorf("%w: missing id", ErrInvalidArgument)
			res.Error = err.Error()
			return
		}
		var acl types.NetworkACL
		var out []byte
		acl, err = db.MeshDB().Networking().GetNetworkACL(ctx, id)
		if err != nil {
			res.Error = err.Error()
			return
		}
		out, err = acl.MarshalProtoJSON()
		if err != nil {
			err = fmt.Errorf("failed to marshal network acl: %w", err)
			res.Error = err.Error()
			return
		}
		res.Items = append(res.Items, out)

	case v1.QueryRequest_ROLES:
		id, ok := req.Filters().GetID()
		if !ok {
			err = fmt.Errorf("%w: missing id", ErrInvalidArgument)
			res.Error = err.Error()
			return
		}
		var role types.Role
		var out []byte
		role, err = db.MeshDB().RBAC().GetRole(ctx, id)
		if err != nil {
			res.Error = err.Error()
			return
		}
		out, err = role.MarshalProtoJSON()
		if err != nil {
			err = fmt.Errorf("failed to marshal role: %w", err)
			res.Error = err.Error()
			return
		}
		res.Items = append(res.Items, out)

	case v1.QueryRequest_ROLEBINDINGS:
		id, ok := req.Filters().GetID()
		if !ok {
			err = fmt.Errorf("%w: missing id", ErrInvalidArgument)
			res.Error = err.Error()
			return
		}
		var rb types.RoleBinding
		var out []byte
		rb, err = db.MeshDB().RBAC().GetRoleBinding(ctx, id)
		if err != nil {
			res.Error = err.Error()
			return
		}
		out, err = rb.MarshalProtoJSON()
		if err != nil {
			err = fmt.Errorf("failed to marshal rolebinding: %w", err)
			res.Error = err.Error()
			return
		}
		res.Items = append(res.Items, out)

	case v1.QueryRequest_GROUPS:
		id, ok := req.Filters().GetID()
		if !ok {
			err = fmt.Errorf("%w: missing id", ErrInvalidArgument)
			res.Error = err.Error()
			return
		}
		var group types.Group
		var out []byte
		group, err = db.MeshDB().RBAC().GetGroup(ctx, id)
		if err != nil {
			res.Error = err.Error()
			return
		}
		out, err = group.MarshalProtoJSON()
		if err != nil {
			err = fmt.Errorf("failed to marshal group: %w", err)
			res.Error = err.Error()
			return
		}
		res.Items = append(res.Items, out)

	case v1.QueryRequest_NETWORK_STATE:
		var state types.NetworkState
		var out []byte
		state, err = db.MeshDB().MeshState().GetMeshState(ctx)
		if err != nil {
			res.Error = err.Error()
			return
		}
		out, err = state.MarshalProtoJSON()
		if err != nil {
			res.Error = err.Error()
			return
		}
		res.Items = append(res.Items, out)

	case v1.QueryRequest_RBAC_STATE:
		var enabled bool
		enabled, err = db.MeshDB().RBAC().GetEnabled(ctx)
		if err != nil {
			res.Error = err.Error()
			return
		}
		res.Items = append(res.Items, []byte(fmt.Sprintf("%t", enabled)))

	default:
		err = fmt.Errorf("%w: unsupported GET query type %s", ErrInvalidQuery, req.GetType().String())
		res.Error = err.Error()
		return
	}
	// Fallthrough not found for multi-select queries.
	if len(res.Items) == 0 {
		res.Error = errors.ErrNotFound.Error()
	}
	return
}

func doListQuery(ctx context.Context, db storage.Provider, req types.StorageQuery) (res *v1.QueryResponse) {
	res = &v1.QueryResponse{}
	var err error
	switch req.GetType() {
	case v1.QueryRequest_VALUE:
		// Support legacy iter queries.
		prefix, _ := req.Filters().GetID()
		err = db.MeshStorage().IterPrefix(ctx, []byte(prefix), func(key []byte, value []byte) error {
			res.Items = append(res.Items, value)
			return nil
		})
		if err != nil {
			res.Error = err.Error()
			return
		}

	case v1.QueryRequest_KEYS:
		// Support legacy iter queries.
		prefix, _ := req.Filters().GetID()
		var keys [][]byte
		keys, err = db.MeshStorage().ListKeys(ctx, []byte(prefix))
		if err != nil {
			res.Error = err.Error()
			return
		}
		res.Items = append(res.Items, keys...)

	case v1.QueryRequest_PEERS:
		var peers []types.MeshNode
		peers, err = db.MeshDB().Peers().List(ctx)
		if err != nil {
			res.Error = err.Error()
			return
		}
		for _, peer := range peers {
			var out []byte
			out, err = peer.MarshalProtoJSON()
			if err != nil {
				err = fmt.Errorf("failed to marshal peer: %w", err)
				res.Error = err.Error()
				return
			}
			res.Items = append(res.Items, out)
		}

	case v1.QueryRequest_EDGES:
		var edges []graph.Edge[types.NodeID]
		edges, err = db.MeshDB().GraphStore().ListEdges()
		if err != nil {
			res.Error = err.Error()
			return
		}
		for _, edge := range edges {
			var out []byte
			out, err = types.Edge(edge).ToMeshEdge(edge.Source, edge.Target).MarshalProtoJSON()
			if err != nil {
				err = fmt.Errorf("failed to marshal edge: %w", err)
				res.Error = err.Error()
				return
			}
			res.Items = append(res.Items, out)
		}

	case v1.QueryRequest_ROUTES:
		// Routes can optionally be filtered by node ID or CIDR.
		var routes []types.Route
		if nodeID, ok := req.Filters().GetNodeID(); ok {
			routes, err = db.MeshDB().Networking().GetRoutesByNode(ctx, nodeID)
			if err != nil {
				res.Error = err.Error()
				return
			}
			for _, route := range routes {
				var out []byte
				out, err = route.MarshalProtoJSON()
				if err != nil {
					err = fmt.Errorf("failed to marshal edge: %w", err)
					res.Error = err.Error()
					return
				}
				res.Items = append(res.Items, out)
			}
		} else if cidr, ok := req.Filters().GetCIDR(); ok {
			routes, err = db.MeshDB().Networking().GetRoutesByCIDR(ctx, cidr)
			if err != nil {
				res.Error = err.Error()
				return
			}
			for _, route := range routes {
				var out []byte
				out, err = route.MarshalProtoJSON()
				if err != nil {
					err = fmt.Errorf("failed to marshal route: %w", err)
					res.Error = err.Error()
					return
				}
				res.Items = append(res.Items, out)
			}
		} else {
			// List all routes
			routes, err = db.MeshDB().Networking().ListRoutes(ctx)
			if err != nil {
				res.Error = err.Error()
				return
			}
			for _, route := range routes {
				var out []byte
				out, err = route.MarshalProtoJSON()
				if err != nil {
					err = fmt.Errorf("failed to marshal route: %w", err)
					res.Error = err.Error()
					return
				}
				res.Items = append(res.Items, out)
			}
		}

	case v1.QueryRequest_ACLS:
		// List all network ACLs.
		var acls []types.NetworkACL
		acls, err = db.MeshDB().Networking().ListNetworkACLs(ctx)
		if err != nil {
			res.Error = err.Error()
			return
		}
		for _, acl := range acls {
			var out []byte
			out, err = acl.MarshalProtoJSON()
			if err != nil {
				err = fmt.Errorf("failed to marshal network ACL: %w", err)
				res.Error = err.Error()
				return
			}
			res.Items = append(res.Items, out)
		}

	case v1.QueryRequest_ROLES:
		// Roles can be filtered by node ID.
		var roles []types.Role
		if nodeID, ok := req.Filters().GetNodeID(); ok {
			roles, err = db.MeshDB().RBAC().ListNodeRoles(ctx, nodeID)
			if err != nil {
				res.Error = err.Error()
				return
			}
			for _, role := range roles {
				var out []byte
				out, err = role.MarshalProtoJSON()
				if err != nil {
					err = fmt.Errorf("failed to marshal role: %w", err)
					res.Error = err.Error()
					return
				}
				res.Items = append(res.Items, out)
			}
		} else {
			// List all roles
			roles, err = db.MeshDB().RBAC().ListRoles(ctx)
			if err != nil {
				res.Error = err.Error()
				return
			}
			for _, role := range roles {
				var out []byte
				out, err = role.MarshalProtoJSON()
				if err != nil {
					err = fmt.Errorf("failed to marshal role: %w", err)
					res.Error = err.Error()
					return
				}
				res.Items = append(res.Items, out)
			}
		}

	case v1.QueryRequest_ROLEBINDINGS:
		var rbs []types.RoleBinding
		rbs, err = db.MeshDB().RBAC().ListRoleBindings(ctx)
		if err != nil {
			res.Error = err.Error()
			return
		}
		for _, rb := range rbs {
			var out []byte
			out, err = rb.MarshalProtoJSON()
			if err != nil {
				err = fmt.Errorf("failed to marshal rolebinding: %w", err)
				res.Error = err.Error()
				return
			}
			res.Items = append(res.Items, out)
		}

	case v1.QueryRequest_GROUPS:
		var groups []types.Group
		groups, err = db.MeshDB().RBAC().ListGroups(ctx)
		if err != nil {
			res.Error = err.Error()
			return
		}
		for _, group := range groups {
			var out []byte
			out, err = group.MarshalProtoJSON()
			if err != nil {
				err = fmt.Errorf("failed to marshal group: %w", err)
				res.Error = err.Error()
				return
			}
			res.Items = append(res.Items, out)
		}

	default:
		err = fmt.Errorf("%w: unsupported LIST query type %s", ErrInvalidQuery, req.GetType().String())
		res.Error = err.Error()
		return
	}
	return
}

func doPutQuery(ctx context.Context, db storage.Provider, req types.StorageQuery) (res *v1.QueryResponse) {
	res = &v1.QueryResponse{}
	switch req.GetType() {
	case v1.QueryRequest_VALUE:
		id, ok := req.Filters().GetID()
		if !ok {
			res.Error = fmt.Errorf("%w: missing id", ErrInvalidArgument).Error()
			return
		}
		// TODO: Support TTLs? This is a legacy format anyway and should be removed.
		err := db.MeshStorage().PutValue(ctx, []byte(id), req.GetItem(), 0)
		if err != nil {
			res.Error = err.Error()
		}

	case v1.QueryRequest_PEERS:
		var peer types.MeshNode
		err := peer.UnmarshalProtoJSON(req.GetItem())
		if err != nil {
			res.Error = err.Error()
			return
		}
		err = db.MeshDB().Peers().Put(ctx, peer)
		if err != nil {
			res.Error = err.Error()
		}

	case v1.QueryRequest_EDGES:
		var edge types.MeshEdge
		err := edge.UnmarshalProtoJSON(req.GetItem())
		if err != nil {
			res.Error = err.Error()
			return
		}
		err = db.MeshDB().Peers().PutEdge(ctx, edge)
		if err != nil {
			res.Error = err.Error()
		}

	case v1.QueryRequest_ROUTES:
		var route types.Route
		err := route.UnmarshalProtoJSON(req.GetItem())
		if err != nil {
			res.Error = err.Error()
			return
		}
		err = db.MeshDB().Networking().PutRoute(ctx, route)
		if err != nil {
			res.Error = err.Error()
		}

	case v1.QueryRequest_ACLS:
		var acl types.NetworkACL
		err := acl.UnmarshalProtoJSON(req.GetItem())
		if err != nil {
			res.Error = err.Error()
			return
		}
		err = db.MeshDB().Networking().PutNetworkACL(ctx, acl)
		if err != nil {
			res.Error = err.Error()
		}

	case v1.QueryRequest_ROLES:
		var role types.Role
		err := role.UnmarshalProtoJSON(req.GetItem())
		if err != nil {
			res.Error = err.Error()
			return
		}
		err = db.MeshDB().RBAC().PutRole(ctx, role)
		if err != nil {
			res.Error = err.Error()
		}

	case v1.QueryRequest_ROLEBINDINGS:
		var rb types.RoleBinding
		err := rb.UnmarshalProtoJSON(req.GetItem())
		if err != nil {
			res.Error = err.Error()
			return
		}
		err = db.MeshDB().RBAC().PutRoleBinding(ctx, rb)
		if err != nil {
			res.Error = err.Error()
		}

	case v1.QueryRequest_GROUPS:
		var group types.Group
		err := group.UnmarshalProtoJSON(req.GetItem())
		if err != nil {
			res.Error = err.Error()
			return
		}
		err = db.MeshDB().RBAC().PutGroup(ctx, group)
		if err != nil {
			res.Error = err.Error()
		}

	default:
		res.Error = fmt.Errorf("%w: unsupported PUT query type %s", ErrInvalidQuery, req.GetType().String()).Error()
	}
	return
}

func doDeleteQuery(ctx context.Context, db storage.Provider, req types.StorageQuery) (res *v1.QueryResponse) {
	res = &v1.QueryResponse{}
	switch req.GetType() {
	case v1.QueryRequest_VALUE:
		id, ok := req.Filters().GetID()
		if !ok {
			res.Error = fmt.Errorf("%w: missing id", ErrInvalidArgument).Error()
			return
		}
		err := db.MeshStorage().Delete(ctx, []byte(id))
		if err != nil {
			res.Error = err.Error()
		}

	case v1.QueryRequest_PEERS:
		id, ok := req.Filters().GetID()
		if !ok {
			res.Error = fmt.Errorf("%w: missing id", ErrInvalidArgument).Error()
			return
		}
		err := db.MeshDB().Peers().Delete(ctx, types.NodeID(id))
		if err != nil {
			res.Error = err.Error()
		}

	case v1.QueryRequest_EDGES:
		source, ok := req.Filters().GetSourceNodeID()
		if !ok {
			res.Error = fmt.Errorf("%w: missing source id", ErrInvalidArgument).Error()
			return
		}
		target, ok := req.Filters().GetTargetNodeID()
		if !ok {
			res.Error = fmt.Errorf("%w: missing target id", ErrInvalidArgument).Error()
			return
		}
		err := db.MeshDB().Peers().RemoveEdge(ctx, source, target)
		if err != nil {
			res.Error = err.Error()
		}

	case v1.QueryRequest_ROUTES:
		id, ok := req.Filters().GetID()
		if !ok {
			res.Error = fmt.Errorf("%w: missing id", ErrInvalidArgument).Error()
			return
		}
		err := db.MeshDB().Networking().DeleteRoute(ctx, id)
		if err != nil {
			res.Error = err.Error()
		}

	case v1.QueryRequest_ACLS:
		id, ok := req.Filters().GetID()
		if !ok {
			res.Error = fmt.Errorf("%w: missing id", ErrInvalidArgument).Error()
			return
		}
		err := db.MeshDB().Networking().DeleteNetworkACL(ctx, id)
		if err != nil {
			res.Error = err.Error()
		}

	case v1.QueryRequest_ROLES:
		id, ok := req.Filters().GetID()
		if !ok {
			res.Error = fmt.Errorf("%w: missing id", ErrInvalidArgument).Error()
			return
		}
		err := db.MeshDB().RBAC().DeleteRole(ctx, id)
		if err != nil {
			res.Error = err.Error()
		}

	case v1.QueryRequest_ROLEBINDINGS:
		id, ok := req.Filters().GetID()
		if !ok {
			res.Error = fmt.Errorf("%w: missing id", ErrInvalidArgument).Error()
			return
		}
		err := db.MeshDB().RBAC().DeleteRoleBinding(ctx, id)
		if err != nil {
			res.Error = err.Error()
		}

	case v1.QueryRequest_GROUPS:
		id, ok := req.Filters().GetID()
		if !ok {
			res.Error = fmt.Errorf("%w: missing id", ErrInvalidArgument).Error()
			return
		}
		err := db.MeshDB().RBAC().DeleteGroup(ctx, id)
		if err != nil {
			res.Error = err.Error()
		}

	default:
		res.Error = fmt.Errorf("%w: unsupported DELETE query type %s", ErrInvalidQuery, req.GetType().String()).Error()
	}
	return
}
