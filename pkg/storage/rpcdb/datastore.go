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

// Package rpcdb provides a meshdb that operates over RPC.
package rpcdb

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/dominikbraun/graph"
	v1 "github.com/webmeshproj/api/go/v1"

	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// RPCDataStore is a MeshDataStore that operates over RPC.
type RPCDataStore struct {
	Querier
}

// GraphStore returns the interface for managing network topology and data about peers.
func (pdb *RPCDataStore) GraphStore() storage.GraphStore {
	return &GraphStore{pdb}
}

// RBAC returns the interface for managing RBAC policies in the mesh.
func (pdb *RPCDataStore) RBAC() storage.RBAC {
	return &RBACStore{pdb}
}

// MeshState returns the interface for querying mesh state.
func (pdb *RPCDataStore) MeshState() storage.MeshState {
	return &MeshStateStore{pdb}
}

// Networking returns the interface for managing networking in the mesh.
func (pdb *RPCDataStore) Networking() storage.Networking {
	return &NetworkingStore{pdb}
}

// KVStorage implements a mesh key-value store over a plugin query stream.
type KVStorage struct {
	Querier
}

// GetValue returns the value of a key.
func (p *KVStorage) GetValue(ctx context.Context, key []byte) ([]byte, error) {
	if !types.IsValidPathID(string(key)) {
		return nil, errors.ErrInvalidKey
	}
	resp, err := p.Query(ctx, &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_VALUE,
		Query:   types.NewQueryFilters().WithID(string(key)).Encode(),
	})
	if err != nil {
		return nil, err
	}
	if resp.GetError() != "" {
		if strings.Contains(err.Error(), "not found") {
			return nil, errors.ErrKeyNotFound
		}
		return nil, fmt.Errorf(resp.GetError())
	}
	if len(resp.GetItems()) == 0 {
		return nil, errors.ErrKeyNotFound
	}
	return resp.GetItems()[0], nil
}

func (p *KVStorage) PutValue(ctx context.Context, key, value []byte, ttl time.Duration) error {
	resp, err := p.Query(ctx, &v1.QueryRequest{
		Command: v1.QueryRequest_PUT,
		Type:    v1.QueryRequest_VALUE,
		Query:   types.NewQueryFilters().WithID(string(key)).Encode(),
		Item:    value,
	})
	if err != nil {
		return err
	}
	if resp.GetError() != "" {
		return fmt.Errorf(resp.GetError())
	}
	return nil
}

func (p *KVStorage) Delete(ctx context.Context, key []byte) error {
	resp, err := p.Query(ctx, &v1.QueryRequest{
		Command: v1.QueryRequest_DELETE,
		Type:    v1.QueryRequest_VALUE,
		Query:   types.NewQueryFilters().WithID(string(key)).Encode(),
	})
	if err != nil {
		return err
	}
	if resp.GetError() != "" {
		return fmt.Errorf(resp.GetError())
	}
	return nil
}

func (p *KVStorage) ListKeys(ctx context.Context, prefix []byte) ([][]byte, error) {
	resp, err := p.Query(ctx, &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_KEYS,
		Query:   types.NewQueryFilters().WithID(string(prefix)).Encode(),
	})
	if err != nil {
		return nil, err
	}
	return resp.GetItems(), nil
}

func (p *KVStorage) IterPrefix(ctx context.Context, prefix []byte, fn storage.PrefixIterator) error {
	keys, err := p.ListKeys(ctx, prefix)
	if err != nil {
		return err
	}
	for _, key := range keys {
		value, err := p.GetValue(ctx, key)
		if err != nil {
			return err
		}
		if err := fn(key, value); err != nil {
			return err
		}
	}
	return nil
}

func (p *KVStorage) Subscribe(ctx context.Context, prefix []byte, fn storage.KVSubscribeFunc) (context.CancelFunc, error) {
	return func() {}, errors.ErrNotStorageNode
}

func (p *KVStorage) Close() error {
	return nil
}

// GraphStore implements a mesh graph store over a plugin query stream.
type GraphStore struct {
	*RPCDataStore
}

func (g *GraphStore) AddVertex(nodeID types.NodeID, node types.MeshNode, props graph.VertexProperties) error {
	data, err := node.MarshalProtoJSON()
	if err != nil {
		return err
	}
	resp, err := g.Query(context.Background(), &v1.QueryRequest{
		Command: v1.QueryRequest_PUT,
		Type:    v1.QueryRequest_PEERS,
		Item:    data,
	})
	if err != nil {
		return err
	}
	if resp.GetError() != "" {
		return fmt.Errorf(resp.GetError())
	}
	return nil
}

func (g *GraphStore) Vertex(nodeID types.NodeID) (node types.MeshNode, props graph.VertexProperties, err error) {
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_PEERS,
		Query:   types.NewQueryFilters().WithID(nodeID.String()).Encode(),
	}
	resp, err := g.Query(context.Background(), req)
	if err != nil {
		return node, props, err
	}
	if resp.GetError() != "" {
		if strings.Contains(err.Error(), "not found") {
			return node, props, graph.ErrVertexNotFound
		}
		return node, props, fmt.Errorf(resp.GetError())
	}
	if len(resp.GetItems()) == 0 {
		return node, props, graph.ErrVertexNotFound
	}
	err = node.UnmarshalProtoJSON(resp.GetItems()[0])
	return node, props, err
}

func (g *GraphStore) RemoveVertex(nodeID types.NodeID) error {
	resp, err := g.Query(context.Background(), &v1.QueryRequest{
		Command: v1.QueryRequest_DELETE,
		Type:    v1.QueryRequest_PEERS,
		Query:   types.NewQueryFilters().WithID(nodeID.String()).Encode(),
	})
	if err != nil {
		return err
	}
	if resp.GetError() != "" {
		return fmt.Errorf(resp.GetError())
	}
	return nil
}

func (g *GraphStore) ListVertices() ([]types.NodeID, error) {
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_PEERS,
	}
	resp, err := g.Query(context.Background(), req)
	if err != nil {
		return nil, err
	}
	out := make([]types.NodeID, len(resp.GetItems()))
	for i, item := range resp.GetItems() {
		node := types.MeshNode{}
		err = node.UnmarshalProtoJSON(item)
		if err != nil {
			return nil, err
		}
		out[i] = node.NodeID()
	}
	return out, nil
}

func (g *GraphStore) VertexCount() (int, error) {
	verticies, err := g.ListVertices()
	return len(verticies), err
}

func (g *GraphStore) AddEdge(sourceNode, targetNode types.NodeID, edge graph.Edge[types.NodeID]) error {
	data, err := types.Edge(edge).ToMeshEdge(sourceNode, targetNode).MarshalProtoJSON()
	if err != nil {
		return err
	}
	resp, err := g.Query(context.Background(), &v1.QueryRequest{
		Command: v1.QueryRequest_PUT,
		Type:    v1.QueryRequest_EDGES,
		Item:    data,
	})
	if err != nil {
		return err
	}
	if resp.GetError() != "" {
		return fmt.Errorf(resp.GetError())
	}
	return nil
}

func (g *GraphStore) UpdateEdge(sourceNode, targetNode types.NodeID, edge graph.Edge[types.NodeID]) error {
	return g.AddEdge(sourceNode, targetNode, edge)
}

func (g *GraphStore) RemoveEdge(sourceNode, targetNode types.NodeID) error {
	resp, err := g.Query(context.Background(), &v1.QueryRequest{
		Command: v1.QueryRequest_DELETE,
		Type:    v1.QueryRequest_EDGES,
		Query:   types.NewQueryFilters().WithSourceNodeID(sourceNode).WithTargetNodeID(targetNode).Encode(),
	})
	if err != nil {
		return err
	}
	if resp.GetError() != "" {
		return fmt.Errorf(resp.GetError())
	}
	return nil
}

func (g *GraphStore) Edge(sourceNode, targetNode types.NodeID) (edge graph.Edge[types.NodeID], err error) {
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_EDGES,
		Query:   types.NewQueryFilters().WithSourceNodeID(sourceNode).WithTargetNodeID(targetNode).Encode(),
	}
	resp, err := g.Query(context.Background(), req)
	if resp.GetError() != "" {
		if strings.Contains(err.Error(), "not found") {
			return edge, graph.ErrEdgeNotFound
		}
		return edge, fmt.Errorf(resp.GetError())
	}
	if len(resp.GetItems()) == 0 {
		return edge, graph.ErrEdgeNotFound
	}
	var meshedge types.MeshEdge
	err = meshedge.UnmarshalProtoJSON(resp.GetItems()[0])
	if err != nil {
		return
	}
	edge = meshedge.AsGraphEdge()
	return
}

func (g *GraphStore) ListEdges() ([]graph.Edge[types.NodeID], error) {
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_EDGES,
	}
	resp, err := g.Query(context.Background(), req)
	if err != nil {
		return nil, err
	}
	out := make([]graph.Edge[types.NodeID], len(resp.GetItems()))
	for i, item := range resp.GetItems() {
		var meshedge types.MeshEdge
		err = meshedge.UnmarshalProtoJSON(item)
		if err != nil {
			return nil, err
		}
		out[i] = meshedge.AsGraphEdge()
	}
	return out, nil
}

func (g *GraphStore) Subscribe(ctx context.Context, fn storage.PeerSubscribeFunc) (context.CancelFunc, error) {
	// Currently not used by any users of plugin storage. They instead use the SubscribePeers API.
	return func() {}, errors.ErrNotStorageNode
}

// RBACStore implements a mesh rbac store over a plugin query stream.
type RBACStore struct {
	*RPCDataStore
}

func (r *RBACStore) SetEnabled(ctx context.Context, enabled bool) error {
	return errors.ErrNotStorageNode
}

func (r *RBACStore) GetEnabled(ctx context.Context) (bool, error) {
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_RBAC_STATE,
	}
	resp, err := r.Query(ctx, req)
	if err != nil {
		return false, err
	}
	if len(resp.GetItems()) == 0 {
		return false, errors.ErrNotFound
	}
	val := string(resp.GetItems()[0])
	return strconv.ParseBool(val)
}

func (r *RBACStore) PutRole(ctx context.Context, role types.Role) error {
	data, err := role.MarshalProtoJSON()
	if err != nil {
		return err
	}
	resp, err := r.Query(ctx, &v1.QueryRequest{
		Command: v1.QueryRequest_PUT,
		Type:    v1.QueryRequest_ROLES,
		Item:    data,
	})
	if err != nil {
		return err
	}
	if resp.GetError() != "" {
		return fmt.Errorf(resp.GetError())
	}
	return nil
}

func (r *RBACStore) DeleteRole(ctx context.Context, name string) error {
	resp, err := r.Query(ctx, &v1.QueryRequest{
		Command: v1.QueryRequest_DELETE,
		Type:    v1.QueryRequest_ROLES,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	})
	if err != nil {
		return err
	}
	if resp.GetError() != "" {
		return fmt.Errorf(resp.GetError())
	}
	return nil
}

func (r *RBACStore) PutRoleBinding(ctx context.Context, rolebinding types.RoleBinding) error {
	data, err := rolebinding.MarshalProtoJSON()
	if err != nil {
		return err
	}
	resp, err := r.Query(ctx, &v1.QueryRequest{
		Command: v1.QueryRequest_PUT,
		Type:    v1.QueryRequest_ROLEBINDINGS,
		Item:    data,
	})
	if err != nil {
		return err
	}
	if resp.GetError() != "" {
		return fmt.Errorf(resp.GetError())
	}
	return nil
}

func (r *RBACStore) DeleteRoleBinding(ctx context.Context, name string) error {
	resp, err := r.Query(ctx, &v1.QueryRequest{
		Command: v1.QueryRequest_DELETE,
		Type:    v1.QueryRequest_ROLEBINDINGS,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	})
	if err != nil {
		return err
	}
	if resp.GetError() != "" {
		return fmt.Errorf(resp.GetError())
	}
	return nil
}

func (r *RBACStore) PutGroup(ctx context.Context, group types.Group) error {
	data, err := group.MarshalProtoJSON()
	if err != nil {
		return err
	}
	resp, err := r.Query(ctx, &v1.QueryRequest{
		Command: v1.QueryRequest_PUT,
		Type:    v1.QueryRequest_GROUPS,
		Item:    data,
	})
	if err != nil {
		return err
	}
	if resp.GetError() != "" {
		return fmt.Errorf(resp.GetError())
	}
	return nil
}
func (r *RBACStore) DeleteGroup(ctx context.Context, name string) error {
	resp, err := r.Query(ctx, &v1.QueryRequest{
		Command: v1.QueryRequest_DELETE,
		Type:    v1.QueryRequest_GROUPS,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	})
	if err != nil {
		return err
	}
	if resp.GetError() != "" {
		return fmt.Errorf(resp.GetError())
	}
	return nil
}

func (r *RBACStore) GetRole(ctx context.Context, name string) (types.Role, error) {
	var meshrole types.Role
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_ROLES,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	}
	resp, err := r.Query(ctx, req)
	if err != nil {
		return meshrole, err
	}
	if resp.GetError() != "" {
		if strings.Contains(err.Error(), "not found") {
			return meshrole, errors.ErrRoleNotFound
		}
		return meshrole, fmt.Errorf(resp.GetError())
	}
	if len(resp.GetItems()) == 0 {
		return meshrole, errors.ErrRoleNotFound
	}
	err = meshrole.UnmarshalProtoJSON(resp.GetItems()[0])
	return meshrole, err
}

func (r *RBACStore) ListRoles(ctx context.Context) (types.RolesList, error) {
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ROLES,
	}
	resp, err := r.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	out := make(types.RolesList, len(resp.GetItems()))
	for i, item := range resp.GetItems() {
		var meshrole types.Role
		err = meshrole.UnmarshalProtoJSON(item)
		if err != nil {
			return nil, err
		}
		out[i] = meshrole
	}
	return out, nil
}

func (r *RBACStore) GetRoleBinding(ctx context.Context, name string) (types.RoleBinding, error) {
	var rb types.RoleBinding
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_ROLEBINDINGS,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	}
	resp, err := r.Query(ctx, req)
	if err != nil {
		return rb, err
	}
	if resp.GetError() != "" {
		if strings.Contains(err.Error(), "not found") {
			return rb, errors.ErrRoleBindingNotFound
		}
		return rb, fmt.Errorf(resp.GetError())
	}
	if len(resp.GetItems()) == 0 {
		return rb, errors.ErrRoleBindingNotFound
	}
	err = rb.UnmarshalProtoJSON(resp.GetItems()[0])
	return rb, err
}

func (r *RBACStore) ListRoleBindings(ctx context.Context) ([]types.RoleBinding, error) {
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ROLEBINDINGS,
	}
	resp, err := r.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	out := make([]types.RoleBinding, len(resp.GetItems()))
	for i, item := range resp.GetItems() {
		var rb types.RoleBinding
		err = rb.UnmarshalProtoJSON(item)
		if err != nil {
			return nil, err
		}
		out[i] = rb
	}
	return out, nil
}

func (r *RBACStore) GetGroup(ctx context.Context, name string) (types.Group, error) {
	var group types.Group
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_GROUPS,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	}
	resp, err := r.Query(ctx, req)
	if err != nil {
		return group, err
	}
	if resp.GetError() != "" {
		if strings.Contains(err.Error(), "not found") {
			return group, errors.ErrGroupNotFound
		}
		return group, fmt.Errorf(resp.GetError())
	}
	if len(resp.GetItems()) == 0 {
		return group, errors.ErrGroupNotFound
	}
	err = group.UnmarshalProtoJSON(resp.GetItems()[0])
	return group, err
}

func (r *RBACStore) ListGroups(ctx context.Context) ([]types.Group, error) {
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_GROUPS,
	}
	resp, err := r.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	out := make([]types.Group, len(resp.GetItems()))
	for i, item := range resp.GetItems() {
		var grp types.Group
		err = grp.UnmarshalProtoJSON(item)
		if err != nil {
			return nil, err
		}
		out[i] = grp
	}
	return out, nil
}

func (r *RBACStore) ListNodeRoles(ctx context.Context, nodeID types.NodeID) (types.RolesList, error) {
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ROLES,
		Query:   types.NewQueryFilters().WithNodeID(nodeID).Encode(),
	}
	resp, err := r.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	out := make(types.RolesList, len(resp.GetItems()))
	for i, item := range resp.GetItems() {
		var meshrole types.Role
		err = meshrole.UnmarshalProtoJSON(item)
		if err != nil {
			return nil, err
		}
		out[i] = meshrole
	}
	return out, nil
}

func (r *RBACStore) ListUserRoles(ctx context.Context, user types.NodeID) (types.RolesList, error) {
	return r.ListNodeRoles(ctx, user)
}

// MeshStateStore implements a mesh state store over a plugin query stream.
type MeshStateStore struct {
	*RPCDataStore
}

func (st *MeshStateStore) SetMeshState(ctx context.Context, state types.NetworkState) error {
	return errors.ErrNotStorageNode
}

func (st *MeshStateStore) GetMeshState(ctx context.Context) (types.NetworkState, error) {
	var state types.NetworkState
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_NETWORK_STATE,
	}
	resp, err := st.Query(ctx, req)
	if err != nil {
		return state, err
	}
	if resp.GetError() != "" {
		return state, fmt.Errorf(resp.GetError())
	}
	if len(resp.GetItems()) == 0 {
		return state, errors.ErrNotFound
	}
	return state, state.UnmarshalProtoJSON(resp.GetItems()[0])
}

// NetworkingStore implements a mesh networking store over a plugin query stream.
type NetworkingStore struct {
	*RPCDataStore
}

func (nw *NetworkingStore) PutNetworkACL(ctx context.Context, acl types.NetworkACL) error {
	data, err := acl.MarshalProtoJSON()
	if err != nil {
		return err
	}
	resp, err := nw.Query(ctx, &v1.QueryRequest{
		Command: v1.QueryRequest_PUT,
		Type:    v1.QueryRequest_ACLS,
		Item:    data,
	})
	if err != nil {
		return err
	}
	if resp.GetError() != "" {
		return fmt.Errorf(resp.GetError())
	}
	return nil
}

func (nw *NetworkingStore) GetNetworkACL(ctx context.Context, name string) (types.NetworkACL, error) {
	var acl types.NetworkACL
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_ACLS,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	}
	resp, err := nw.Query(ctx, req)
	if err != nil {
		return acl, err
	}
	if resp.GetError() != "" {
		if strings.Contains(err.Error(), "not found") {
			return acl, errors.ErrACLNotFound
		}
		return acl, fmt.Errorf(resp.GetError())
	}
	if len(resp.GetItems()) == 0 {
		return acl, errors.ErrACLNotFound
	}
	err = acl.UnmarshalProtoJSON(resp.GetItems()[0])
	return acl, err
}

func (nw *NetworkingStore) DeleteNetworkACL(ctx context.Context, name string) error {
	resp, err := nw.Query(ctx, &v1.QueryRequest{
		Command: v1.QueryRequest_DELETE,
		Type:    v1.QueryRequest_ACLS,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	})
	if err != nil {
		return err
	}
	if resp.GetError() != "" {
		return fmt.Errorf(resp.GetError())
	}
	return nil
}

func (nw *NetworkingStore) ListNetworkACLs(ctx context.Context) (types.NetworkACLs, error) {
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ACLS,
	}
	resp, err := nw.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	out := make(types.NetworkACLs, len(resp.GetItems()))
	for i, item := range resp.GetItems() {
		var acl types.NetworkACL
		err = acl.UnmarshalProtoJSON(item)
		if err != nil {
			return nil, err
		}
		out[i] = acl
	}
	return out, nil
}

func (nw *NetworkingStore) PutRoute(ctx context.Context, route types.Route) error {
	data, err := route.MarshalProtoJSON()
	if err != nil {
		return err
	}
	resp, err := nw.Query(ctx, &v1.QueryRequest{
		Command: v1.QueryRequest_PUT,
		Type:    v1.QueryRequest_ROUTES,
		Item:    data,
	})
	if err != nil {
		return err
	}
	if resp.GetError() != "" {
		return fmt.Errorf(resp.GetError())
	}
	return nil
}

func (nw *NetworkingStore) GetRoute(ctx context.Context, name string) (types.Route, error) {
	var route types.Route
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_ROUTES,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	}
	resp, err := nw.Query(ctx, req)
	if err != nil {
		return route, err
	}
	if resp.GetError() != "" {
		if strings.Contains(err.Error(), "not found") {
			return route, errors.ErrRouteNotFound
		}
		return route, fmt.Errorf(resp.GetError())
	}
	if len(resp.GetItems()) == 0 {
		return route, errors.ErrRouteNotFound
	}
	err = route.UnmarshalProtoJSON(resp.GetItems()[0])
	return route, err
}

func (nw *NetworkingStore) GetRoutesByNode(ctx context.Context, nodeID types.NodeID) (types.Routes, error) {
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ROUTES,
		Query:   types.NewQueryFilters().WithNodeID(nodeID).Encode(),
	}
	resp, err := nw.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	out := make(types.Routes, len(resp.GetItems()))
	for i, item := range resp.GetItems() {
		var route types.Route
		err = route.UnmarshalProtoJSON(item)
		if err != nil {
			return nil, err
		}
		out[i] = route
	}
	return out, nil
}

func (nw *NetworkingStore) GetRoutesByCIDR(ctx context.Context, cidr netip.Prefix) (types.Routes, error) {
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ROUTES,
		Query:   types.NewQueryFilters().WithCIDR(cidr).Encode(),
	}
	resp, err := nw.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	out := make(types.Routes, len(resp.GetItems()))
	for i, item := range resp.GetItems() {
		var route types.Route
		err = route.UnmarshalProtoJSON(item)
		if err != nil {
			return nil, err
		}
		out[i] = route
	}
	return out, nil
}

func (nw *NetworkingStore) DeleteRoute(ctx context.Context, name string) error {
	resp, err := nw.Query(ctx, &v1.QueryRequest{
		Command: v1.QueryRequest_DELETE,
		Type:    v1.QueryRequest_ROUTES,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	})
	if err != nil {
		return err
	}
	if resp.GetError() != "" {
		return fmt.Errorf(resp.GetError())
	}
	return nil
}

func (nw *NetworkingStore) ListRoutes(ctx context.Context) (types.Routes, error) {
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ROUTES,
	}
	resp, err := nw.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	out := make(types.Routes, len(resp.GetItems()))
	for i, item := range resp.GetItems() {
		var route types.Route
		err = route.UnmarshalProtoJSON(item)
		if err != nil {
			return nil, err
		}
		out[i] = route
	}
	return out, nil
}
