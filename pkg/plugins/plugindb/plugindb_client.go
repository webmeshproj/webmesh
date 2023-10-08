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

// Package plugindb contains an interface for performing storage queries
// over the storage APIs.
package plugindb

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dominikbraun/graph"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// QueryServer is the query server interface.
type QueryServer interface {
	// The underlying gRPC stream.
	grpc.ServerStream
	// Send sends a query request to the plugin.
	Send(*v1.QueryRequest) error
	// Recv receives a query result from the plugin.
	Recv() (*v1.QueryResponse, error)
}

// Open opens a new database connection to a plugin query stream.
func OpenDB(srv QueryServer) storage.MeshDB {
	return meshdb.New(&PluginDataStore{QueryServer: srv})
}

// OpenKeyVal opens a new key-value store connection to a plugin query stream.
func OpenKeyVal(srv QueryServer) storage.MeshStorage {
	return &PluginMeshStorage{QueryServer: srv}
}

// PluginMeshStorage implements a mesh key-value store over a plugin query stream.
type PluginMeshStorage struct {
	QueryServer
	mu sync.Mutex
}

// GetValue returns the value of a key.
func (p *PluginMeshStorage) GetValue(ctx context.Context, key []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !types.IsValidPathID(string(key)) {
		return nil, errors.ErrInvalidKey
	}
	err := p.Send(&v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_VALUE,
		Query:   types.NewQueryFilters().WithID(string(key)).Encode(),
	})
	if err != nil {
		return nil, err
	}
	resp, err := p.Recv()
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

func (p *PluginMeshStorage) PutValue(ctx context.Context, key, value []byte, ttl time.Duration) error {
	return errors.ErrNotStorageNode
}

func (p *PluginMeshStorage) Delete(ctx context.Context, key []byte) error {
	return errors.ErrNotStorageNode
}

func (p *PluginMeshStorage) ListKeys(ctx context.Context, prefix []byte) ([][]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	err := p.Send(&v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_KEYS,
		Query:   types.NewQueryFilters().WithID(string(prefix)).Encode(),
	})
	if err != nil {
		return nil, err
	}
	resp, err := p.Recv()
	if err != nil {
		return nil, err
	}
	return resp.GetItems(), nil
}

func (p *PluginMeshStorage) IterPrefix(ctx context.Context, prefix []byte, fn storage.PrefixIterator) error {
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

func (p *PluginMeshStorage) Subscribe(ctx context.Context, prefix []byte, fn storage.KVSubscribeFunc) (context.CancelFunc, error) {
	return func() {}, errors.ErrNotStorageNode
}

func (p *PluginMeshStorage) Close() error {
	return nil
}

// PluginDataStore implements a mesh data store over a plugin query stream.
type PluginDataStore struct {
	QueryServer
	mu sync.Mutex
}

// GraphStore returns the interface for managing network topology and data
// about peers.
func (pdb *PluginDataStore) GraphStore() storage.GraphStore {
	return &GraphStore{pdb}
}

// RBAC returns the interface for managing RBAC policies in the mesh.
func (pdb *PluginDataStore) RBAC() storage.RBAC {
	return &RBACStore{pdb}
}

// MeshState returns the interface for querying mesh state.
func (pdb *PluginDataStore) MeshState() storage.MeshState {
	return &MeshStateStore{pdb}
}

// Networking returns the interface for managing networking in the mesh.
func (pdb *PluginDataStore) Networking() storage.Networking {
	return &NetworkingStore{pdb}
}

// GraphStore implements a mesh graph store over a plugin query stream.
type GraphStore struct {
	*PluginDataStore
}

func (g *GraphStore) AddVertex(nodeID types.NodeID, node types.MeshNode, props graph.VertexProperties) error {
	return errors.ErrNotStorageNode
}

func (g *GraphStore) Vertex(nodeID types.NodeID) (node types.MeshNode, props graph.VertexProperties, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_PEERS,
		Query:   types.NewQueryFilters().WithID(nodeID.String()).Encode(),
	}
	err = g.Send(req)
	if err != nil {
		return node, props, err
	}
	var resp *v1.QueryResponse
	resp, err = g.Recv()
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
	return errors.ErrNotStorageNode
}

func (g *GraphStore) ListVertices() ([]types.NodeID, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_PEERS,
	}
	err := g.Send(req)
	if err != nil {
		return nil, err
	}
	var resp *v1.QueryResponse
	resp, err = g.Recv()
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
	return errors.ErrNotStorageNode
}

func (g *GraphStore) UpdateEdge(sourceNode, targetNode types.NodeID, edge graph.Edge[types.NodeID]) error {
	return errors.ErrNotStorageNode
}

func (g *GraphStore) RemoveEdge(sourceNode, targetNode types.NodeID) error {
	return errors.ErrNotStorageNode
}

func (g *GraphStore) Edge(sourceNode, targetNode types.NodeID) (edge graph.Edge[types.NodeID], err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_EDGES,
		Query:   types.NewQueryFilters().WithSourceNodeID(sourceNode).WithTargetNodeID(targetNode).Encode(),
	}
	err = g.Send(req)
	if err != nil {
		return edge, err
	}
	var resp *v1.QueryResponse
	resp, err = g.Recv()
	if err != nil {
		return edge, err
	}
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
	g.mu.Lock()
	defer g.mu.Unlock()
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_EDGES,
	}
	err := g.Send(req)
	if err != nil {
		return nil, err
	}
	var resp *v1.QueryResponse
	resp, err = g.Recv()
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
	// Currently not used by any users of passthrough storage. They instead use the SubscribePeers API.
	return func() {}, errors.ErrNotStorageNode
}

// RBACStore implements a mesh rbac store over a plugin query stream.
type RBACStore struct {
	*PluginDataStore
}

func (r *RBACStore) SetEnabled(ctx context.Context, enabled bool) error {
	return errors.ErrNotStorageNode
}

func (r *RBACStore) GetEnabled(ctx context.Context) (bool, error) {
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_RBAC_STATE,
	}
	err := r.Send(req)
	if err != nil {
		return false, err
	}
	var resp *v1.QueryResponse
	resp, err = r.Recv()
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
	return errors.ErrNotStorageNode
}

func (r *RBACStore) DeleteRole(ctx context.Context, name string) error {
	return errors.ErrNotStorageNode
}

func (r *RBACStore) PutRoleBinding(ctx context.Context, rolebinding types.RoleBinding) error {
	return errors.ErrNotStorageNode
}

func (r *RBACStore) DeleteRoleBinding(ctx context.Context, name string) error {
	return errors.ErrNotStorageNode
}

func (r *RBACStore) PutGroup(ctx context.Context, group types.Group) error {
	return errors.ErrNotStorageNode
}
func (r *RBACStore) DeleteGroup(ctx context.Context, name string) error {
	return errors.ErrNotStorageNode
}

func (r *RBACStore) GetRole(ctx context.Context, name string) (types.Role, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var meshrole types.Role
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_ROLES,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	}
	err := r.Send(req)
	if err != nil {
		return meshrole, err
	}
	var resp *v1.QueryResponse
	resp, err = r.Recv()
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
	r.mu.Lock()
	defer r.mu.Unlock()
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ROLES,
	}
	err := r.Send(req)
	if err != nil {
		return nil, err
	}
	var resp *v1.QueryResponse
	resp, err = r.Recv()
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
	r.mu.Lock()
	defer r.mu.Unlock()
	var rb types.RoleBinding
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_ROLEBINDINGS,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	}
	err := r.Send(req)
	if err != nil {
		return rb, err
	}
	var resp *v1.QueryResponse
	resp, err = r.Recv()
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
	r.mu.Lock()
	defer r.mu.Unlock()
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ROLEBINDINGS,
	}
	err := r.Send(req)
	if err != nil {
		return nil, err
	}
	var resp *v1.QueryResponse
	resp, err = r.Recv()
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
	r.mu.Lock()
	defer r.mu.Unlock()
	var group types.Group
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_GROUPS,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	}
	err := r.Send(req)
	if err != nil {
		return group, err
	}
	var resp *v1.QueryResponse
	resp, err = r.Recv()
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
	r.mu.Lock()
	defer r.mu.Unlock()
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_GROUPS,
	}
	err := r.Send(req)
	if err != nil {
		return nil, err
	}
	var resp *v1.QueryResponse
	resp, err = r.Recv()
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
	r.mu.Lock()
	defer r.mu.Unlock()
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ROLES,
		Query:   types.NewQueryFilters().WithNodeID(nodeID).Encode(),
	}
	err := r.Send(req)
	if err != nil {
		return nil, err
	}
	var resp *v1.QueryResponse
	resp, err = r.Recv()
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
	*PluginDataStore
}

func (st *MeshStateStore) GetIPv6Prefix(ctx context.Context) (netip.Prefix, error) {
	state, err := st.GetMeshState(ctx)
	if err != nil {
		return netip.Prefix{}, err
	}
	return state.NetworkV6(), nil
}

func (st *MeshStateStore) SetIPv6Prefix(ctx context.Context, prefix netip.Prefix) error {
	return errors.ErrNotStorageNode
}

func (st *MeshStateStore) GetIPv4Prefix(ctx context.Context) (netip.Prefix, error) {
	state, err := st.GetMeshState(ctx)
	if err != nil {
		return netip.Prefix{}, err
	}
	return state.NetworkV4(), nil
}

func (st *MeshStateStore) SetIPv4Prefix(ctx context.Context, prefix netip.Prefix) error {
	return errors.ErrNotStorageNode
}

func (st *MeshStateStore) GetMeshDomain(ctx context.Context) (string, error) {
	state, err := st.GetMeshState(ctx)
	if err != nil {
		return "", err
	}
	return state.Domain(), nil
}

func (st *MeshStateStore) SetMeshDomain(ctx context.Context, domain string) error {
	return errors.ErrNotStorageNode
}

func (st *MeshStateStore) GetMeshState(ctx context.Context) (types.NetworkState, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	var state types.NetworkState
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_NETWORK_STATE,
	}
	err := st.Send(req)
	if err != nil {
		return state, err
	}
	var resp *v1.QueryResponse
	resp, err = st.Recv()
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
	*PluginDataStore
}

func (nw *NetworkingStore) PutNetworkACL(ctx context.Context, acl types.NetworkACL) error {
	return errors.ErrNotStorageNode
}

func (nw *NetworkingStore) GetNetworkACL(ctx context.Context, name string) (types.NetworkACL, error) {
	nw.mu.Lock()
	defer nw.mu.Unlock()
	var acl types.NetworkACL
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_ACLS,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	}
	err := nw.Send(req)
	if err != nil {
		return acl, err
	}
	var resp *v1.QueryResponse
	resp, err = nw.Recv()
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
	return errors.ErrNotStorageNode
}

func (nw *NetworkingStore) ListNetworkACLs(ctx context.Context) (types.NetworkACLs, error) {
	nw.mu.Lock()
	defer nw.mu.Unlock()
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ACLS,
	}
	err := nw.Send(req)
	if err != nil {
		return nil, err
	}
	var resp *v1.QueryResponse
	resp, err = nw.Recv()
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
	return errors.ErrNotStorageNode
}

func (nw *NetworkingStore) GetRoute(ctx context.Context, name string) (types.Route, error) {
	nw.mu.Lock()
	defer nw.mu.Unlock()
	var route types.Route
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_ROUTES,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	}
	err := nw.Send(req)
	if err != nil {
		return route, err
	}
	var resp *v1.QueryResponse
	resp, err = nw.Recv()
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
	nw.mu.Lock()
	defer nw.mu.Unlock()
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ROUTES,
		Query:   types.NewQueryFilters().WithNodeID(nodeID).Encode(),
	}
	err := nw.Send(req)
	if err != nil {
		return nil, err
	}
	var resp *v1.QueryResponse
	resp, err = nw.Recv()
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
	nw.mu.Lock()
	defer nw.mu.Unlock()
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ROUTES,
		Query:   types.NewQueryFilters().WithCIDR(cidr).Encode(),
	}
	err := nw.Send(req)
	if err != nil {
		return nil, err
	}
	var resp *v1.QueryResponse
	resp, err = nw.Recv()
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
	return errors.ErrNotStorageNode
}

func (nw *NetworkingStore) ListRoutes(ctx context.Context) (types.Routes, error) {
	nw.mu.Lock()
	defer nw.mu.Unlock()
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ROUTES,
	}
	err := nw.Send(req)
	if err != nil {
		return nil, err
	}
	var resp *v1.QueryResponse
	resp, err = nw.Recv()
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
