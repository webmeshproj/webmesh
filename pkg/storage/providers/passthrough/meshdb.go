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

package passthrough

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/dominikbraun/graph"
	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// MeshDataStore is a passthrough data store that uses the storage API to field read requests.
type MeshDataStore struct {
	dialer transport.NodeDialer
	cli    v1.StorageQueryServiceClient
	conn   *grpc.ClientConn
	graph  storage.GraphStore
	rbac   storage.RBAC
	state  storage.MeshState
	net    storage.Networking
	mu     sync.Mutex
}

// NewMeshDataStore creates a new passthrough data store.
func NewMeshDataStore(dialer transport.NodeDialer) *MeshDataStore {
	db := &MeshDataStore{dialer: dialer}
	db.graph = &GraphStore{db}
	db.rbac = &RBACStore{db}
	db.state = &StateStore{db}
	db.net = &NetworkingStore{db}
	return db
}

func (mdb *MeshDataStore) dial(ctx context.Context) error {
	mdb.mu.Lock()
	defer mdb.mu.Unlock()
	if mdb.conn != nil {
		if mdb.conn.GetState() == connectivity.Shutdown {
			mdb.conn = nil
		} else {
			return nil
		}
	}
	if _, ok := ctx.Deadline(); !ok {
		// Ensure a dial deadline is set.
		// TODO: Make configurable.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Second*5)
		defer cancel()
	}
	var err error
	conn, err := mdb.dialer.DialNode(ctx, "")
	if err != nil {
		return err
	}
	if c, ok := conn.(*grpc.ClientConn); ok {
		mdb.conn = c
	} else {
		defer conn.Close()
		return fmt.Errorf("invalid connection type: %T", conn)
	}
	mdb.cli = v1.NewStorageQueryServiceClient(mdb.conn)
	return nil
}

// GraphStore returns the interface for managing network topology and data
// about peers.
func (mdb *MeshDataStore) GraphStore() storage.GraphStore {
	return mdb.graph
}

// RBAC returns the interface for managing RBAC policies in the mesh.
func (mdb *MeshDataStore) RBAC() storage.RBAC {
	return mdb.rbac
}

// MeshState returns the interface for querying mesh state.
func (mdb *MeshDataStore) MeshState() storage.MeshState {
	return mdb.state
}

// Networking returns the interface for managing networking in the mesh.
func (mdb *MeshDataStore) Networking() storage.Networking {
	return mdb.net
}

// GraphStore is a passthrough graph store that uses the storage API to field
// read requests.
type GraphStore struct {
	*MeshDataStore
}

func (g *GraphStore) AddVertex(nodeID types.NodeID, node types.MeshNode, props graph.VertexProperties) error {
	return errors.ErrNotStorageNode
}

func (g *GraphStore) Vertex(nodeID types.NodeID) (node types.MeshNode, props graph.VertexProperties, err error) {
	ctx := context.Background()
	err = g.dial(ctx)
	if err != nil {
		return node, props, err
	}
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_PEERS,
		Query:   types.NewQueryFilters().WithID(nodeID.String()).Encode(),
	}
	resp, err := g.cli.Query(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return node, props, graph.ErrVertexNotFound
		}
		return node, props, err
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
	ctx := context.Background()
	err := g.dial(ctx)
	if err != nil {
		return nil, err
	}
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_PEERS,
	}
	resp, err := g.cli.Query(ctx, req)
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
	ctx := context.Background()
	err = g.dial(ctx)
	if err != nil {
		return edge, err
	}
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_EDGES,
		Query:   types.NewQueryFilters().WithSourceNodeID(sourceNode).WithTargetNodeID(targetNode).Encode(),
	}
	resp, err := g.cli.Query(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return edge, graph.ErrEdgeNotFound
		}
		return edge, err
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
	ctx := context.Background()
	err := g.dial(ctx)
	if err != nil {
		return nil, err
	}
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_EDGES,
	}
	resp, err := g.cli.Query(ctx, req)
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

// RBACStore is a passthrough RBAC store that uses the storage API to field
// read requests.
type RBACStore struct {
	*MeshDataStore
}

func (r *RBACStore) SetEnabled(ctx context.Context, enabled bool) error {
	return errors.ErrNotStorageNode
}

func (r *RBACStore) GetEnabled(ctx context.Context) (bool, error) {
	err := r.dial(ctx)
	if err != nil {
		return false, err
	}
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_RBAC_STATE,
	}
	resp, err := r.cli.Query(ctx, req)
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
	var meshrole types.Role
	err := r.dial(ctx)
	if err != nil {
		return meshrole, err
	}
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_ROLES,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	}
	resp, err := r.cli.Query(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return meshrole, errors.ErrRoleNotFound
		}
		return meshrole, err
	}
	if len(resp.GetItems()) == 0 {
		return meshrole, errors.ErrRoleNotFound
	}
	err = meshrole.UnmarshalProtoJSON(resp.GetItems()[0])
	return meshrole, err
}

func (r *RBACStore) ListRoles(ctx context.Context) (types.RolesList, error) {
	err := r.dial(ctx)
	if err != nil {
		return nil, err
	}
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ROLES,
	}
	resp, err := r.cli.Query(ctx, req)
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
	err := r.dial(ctx)
	if err != nil {
		return rb, err
	}
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_ROLEBINDINGS,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	}
	resp, err := r.cli.Query(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return rb, errors.ErrRoleBindingNotFound
		}
		return rb, err
	}
	if len(resp.GetItems()) == 0 {
		return rb, errors.ErrRoleBindingNotFound
	}
	err = rb.UnmarshalProtoJSON(resp.GetItems()[0])
	return rb, err
}

func (r *RBACStore) ListRoleBindings(ctx context.Context) ([]types.RoleBinding, error) {
	err := r.dial(ctx)
	if err != nil {
		return nil, err
	}
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ROLEBINDINGS,
	}
	resp, err := r.cli.Query(ctx, req)
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
	err := r.dial(ctx)
	if err != nil {
		return group, err
	}
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_GROUPS,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	}
	resp, err := r.cli.Query(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return group, errors.ErrGroupNotFound
		}
		return group, err
	}
	if len(resp.GetItems()) == 0 {
		return group, errors.ErrGroupNotFound
	}
	err = group.UnmarshalProtoJSON(resp.GetItems()[0])
	return group, err
}

func (r *RBACStore) ListGroups(ctx context.Context) ([]types.Group, error) {
	err := r.dial(ctx)
	if err != nil {
		return nil, err
	}
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_GROUPS,
	}
	resp, err := r.cli.Query(ctx, req)
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
	err := r.dial(ctx)
	if err != nil {
		return nil, err
	}
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ROLES,
		Query:   types.NewQueryFilters().WithNodeID(nodeID).Encode(),
	}
	resp, err := r.cli.Query(ctx, req)
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

// StateStore is a passthrough state store that uses the storage API to field
// read requests.
type StateStore struct {
	*MeshDataStore
}

func (st *StateStore) SetMeshState(_ context.Context, _ types.NetworkState) error {
	return errors.ErrNotStorageNode
}

func (st *StateStore) GetMeshState(ctx context.Context) (types.NetworkState, error) {
	var state types.NetworkState
	err := st.dial(ctx)
	if err != nil {
		return state, err
	}
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_NETWORK_STATE,
	}
	resp, err := st.cli.Query(ctx, req)
	if err != nil {
		return state, err
	}
	if len(resp.GetItems()) == 0 {
		return state, errors.ErrNotFound
	}
	return state, state.UnmarshalProtoJSON(resp.GetItems()[0])
}

// NetworkingStore is a passthrough networking store that uses the storage API
// to field read requests.
type NetworkingStore struct {
	*MeshDataStore
}

func (nw *NetworkingStore) PutNetworkACL(ctx context.Context, acl types.NetworkACL) error {
	return errors.ErrNotStorageNode
}

func (nw *NetworkingStore) GetNetworkACL(ctx context.Context, name string) (types.NetworkACL, error) {
	var acl types.NetworkACL
	err := nw.dial(ctx)
	if err != nil {
		return acl, err
	}
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_ACLS,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	}
	resp, err := nw.cli.Query(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return acl, errors.ErrACLNotFound
		}
		return acl, err
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
	err := nw.dial(ctx)
	if err != nil {
		return nil, err
	}
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ACLS,
	}
	resp, err := nw.cli.Query(ctx, req)
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
	var route types.Route
	err := nw.dial(ctx)
	if err != nil {
		return route, err
	}
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_ROUTES,
		Query:   types.NewQueryFilters().WithID(name).Encode(),
	}
	resp, err := nw.cli.Query(ctx, req)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return route, errors.ErrRouteNotFound
		}
		return route, err
	}
	if len(resp.GetItems()) == 0 {
		return route, errors.ErrRouteNotFound
	}
	err = route.UnmarshalProtoJSON(resp.GetItems()[0])
	return route, err
}

func (nw *NetworkingStore) GetRoutesByNode(ctx context.Context, nodeID types.NodeID) (types.Routes, error) {
	err := nw.dial(ctx)
	if err != nil {
		return nil, err
	}
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ROUTES,
		Query:   types.NewQueryFilters().WithNodeID(nodeID).Encode(),
	}
	resp, err := nw.cli.Query(ctx, req)
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
	err := nw.dial(ctx)
	if err != nil {
		return nil, err
	}
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ROUTES,
		Query:   types.NewQueryFilters().WithCIDR(cidr).Encode(),
	}
	resp, err := nw.cli.Query(ctx, req)
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
	err := nw.dial(ctx)
	if err != nil {
		return nil, err
	}
	req := &v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_ROUTES,
	}
	resp, err := nw.cli.Query(ctx, req)
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
