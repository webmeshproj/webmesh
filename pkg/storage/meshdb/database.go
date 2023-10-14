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

// Package meshdb implements a storage.Database using any storage.MeshStorage
// instance.
package meshdb

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/dominikbraun/graph"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb/graphstore"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb/networking"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb/rbac"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb/state"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// New returns a new MeshDB instance using the given underlying MeshDataStore.
// Storage operations will be validated before being passed to the underlying
// MeshDataStore. If the underlying MeshDataStore already performs validation,
// this is redundant. Note that certain write operations will call into read
// methods to perform validation. So any locks used internally must be reentrant.
func New(db storage.MeshDataStore) storage.MeshDB {
	graphStore := &ValidatingGraphStore{db.GraphStore()}
	return &Database{
		db:         db,
		graphStore: graphStore,
		peers: &ValidatingPeerStore{
			graph:      storage.NewGraphWithStore(graphStore),
			graphStore: graphStore,
		},
		rbac:    &ValidatingRBACStore{db.RBAC()},
		state:   &ValidatingMeshStateStore{db.MeshState()},
		network: &ValidatingNetworkingStore{db.Networking()},
	}
}

// NewFromStorage creates a new MeshDB instance from the given MeshStorage. The same
// information applies as for New.
func NewFromStorage(st storage.MeshStorage) storage.MeshDB {
	return New(&MeshDataStore{
		graph:   graphstore.NewStore(st),
		rbac:    rbac.New(st),
		mesh:    state.New(st),
		network: networking.New(st),
	})
}

// MeshDataStore is a data store using an underlying MeshStorage instance.
type MeshDataStore struct {
	graph   storage.GraphStore
	rbac    storage.RBAC
	mesh    storage.MeshState
	network storage.Networking
}

// GraphStore returns the underlying storage.MeshDB's GraphStore instance.
func (m *MeshDataStore) GraphStore() storage.GraphStore {
	return m.graph
}

// RBAC returns the underlying storage.MeshDB's RBAC instance.
func (m *MeshDataStore) RBAC() storage.RBAC {
	return m.rbac
}

// MeshState returns the underlying storage.MeshDB's MeshState instance.
func (m *MeshDataStore) MeshState() storage.MeshState {
	return m.mesh
}

// Networking returns the underlying storage.MeshDB's Networking instance.
func (m *MeshDataStore) Networking() storage.Networking {
	return m.network
}

// Database wraps a storage.MeshDataStore and automatically performs the necessary
// validation on all operations. Note that certain write operations will call into
// read methods to perform validation. So any locks used internally must be reentrant.
type Database struct {
	db         storage.MeshDataStore
	graphStore storage.GraphStore
	peers      storage.Peers
	rbac       storage.RBAC
	state      storage.MeshState
	network    storage.Networking
}

// Peers returns the underlying storage.MeshDB's Peers instance with
// validators run before operations.
func (d *Database) Peers() storage.Peers {
	return d.peers
}

// GraphStore returns the underlying storage.MeshDB's GraphStore instance with
// validators run before operations.
func (d *Database) GraphStore() storage.GraphStore {
	return d.graphStore
}

// RBAC returns the underlying storage.MeshDB's RBAC instance with
// validators run before operations.
func (d *Database) RBAC() storage.RBAC {
	return d.rbac
}

// MeshState returns the underlying storage.MeshDB's MeshState instance with
// validators run before operations.
func (d *Database) MeshState() storage.MeshState {
	return d.state
}

// Networking returns the underlying storage.MeshDB's Networking instance with
// validators run before operations.
func (d *Database) Networking() storage.Networking {
	return d.network
}

// ValidatingMeshStateStore wraps a storage.MeshState and automatically performs the
// necessary validation on all operations.
type ValidatingMeshStateStore struct {
	storage.MeshState
}

// SetMeshDomain sets the mesh domain.
func (v *ValidatingMeshStateStore) SetMeshState(ctx context.Context, state types.NetworkState) error {
	if state.GetDomain() == "" {
		return fmt.Errorf("domain can not be empty")
	}
	if state.GetNetworkV4() != "" {
		_, err := netip.ParsePrefix(state.GetNetworkV4())
		if err != nil {
			return fmt.Errorf("parse IPv4 prefix: %w", err)
		}
	}
	if state.GetNetworkV6() != "" {
		_, err := netip.ParsePrefix(state.GetNetworkV6())
		if err != nil {
			return fmt.Errorf("parse IPv6 prefix: %w", err)
		}
	}
	return v.MeshState.SetMeshState(ctx, state)
}

// GetMeshState returns the mesh state.
func (v *ValidatingMeshStateStore) GetMeshState(ctx context.Context) (types.NetworkState, error) {
	return v.MeshState.GetMeshState(ctx)
}

// ValidatingPeerStore wraps graph store implementation with a simpler to use
// peer store interface.
type ValidatingPeerStore struct {
	graph      types.PeerGraph
	graphStore storage.GraphStore
}

// Graph returns the underlying graph.
func (p *ValidatingPeerStore) Graph() types.PeerGraph {
	return p.graph
}

// Subscribe subscribe to node and edge changes from the underlying graph storage.
func (p *ValidatingPeerStore) Subscribe(ctx context.Context, fn storage.PeerSubscribeFunc) (context.CancelFunc, error) {
	return p.graphStore.Subscribe(ctx, fn)
}

// Put validates the node and then saves it to the underlying graph storage.
func (p *ValidatingPeerStore) Put(ctx context.Context, node types.MeshNode) error {
	validated, err := types.ValidateMeshNode(node)
	if err != nil {
		return fmt.Errorf("validate node: %w", err)
	}
	err = p.graph.AddVertex(validated)
	if err != nil {
		return fmt.Errorf("put node: %w", err)
	}
	return nil
}

// Get validates the node ID and then retrieves it from the underlying graph storage.
func (p *ValidatingPeerStore) Get(ctx context.Context, id types.NodeID) (types.MeshNode, error) {
	if !id.IsValid() {
		return types.MeshNode{}, fmt.Errorf("%w: %s", errors.ErrInvalidNodeID, id)
	}
	node, err := p.graph.Vertex(id)
	if err != nil {
		if errors.Is(err, graph.ErrVertexNotFound) {
			return types.MeshNode{}, errors.ErrNodeNotFound
		}
		return types.MeshNode{}, fmt.Errorf("get node: %w", err)
	}
	return node, nil
}

// GetByPubKey gets a node by their public key.
func (p *ValidatingPeerStore) GetByPubKey(ctx context.Context, key crypto.PublicKey) (types.MeshNode, error) {
	nodes, err := p.List(ctx)
	if err != nil {
		return types.MeshNode{}, fmt.Errorf("list nodes: %w", err)
	}
	for _, node := range nodes {
		if node.GetPublicKey() != "" {
			key, err := crypto.DecodePublicKey(node.GetPublicKey())
			if err != nil {
				return types.MeshNode{}, fmt.Errorf("parse host public key: %w", err)
			}
			if key.Equals(key) {
				return node, nil
			}
		}
	}
	return types.MeshNode{}, errors.ErrNodeNotFound
}

// Delete removes the node by first removing any edges it is a part of and then
// removing it from the graph.
func (p *ValidatingPeerStore) Delete(ctx context.Context, id types.NodeID) error {
	edges, err := p.graph.Edges()
	if err != nil {
		return fmt.Errorf("get edges: %w", err)
	}
	for _, edge := range edges {
		if edge.Source.String() == id.String() || edge.Target.String() == id.String() {
			err = p.graph.RemoveEdge(edge.Source, edge.Target)
			if err != nil {
				return err
			}
		}
	}
	err = p.graph.RemoveVertex(types.NodeID(id))
	if err != nil {
		if errors.Is(err, graph.ErrVertexNotFound) {
			// We don't return this error in the graph store
			// implementation, so we don't return it here either.
			return nil
		}
		return fmt.Errorf("remove vertex: %w", err)
	}
	return nil
}

// List returns all nodes in the graph.
func (p *ValidatingPeerStore) List(ctx context.Context, filters ...storage.PeerFilter) ([]types.MeshNode, error) {
	out := make([]types.MeshNode, 0)
	verticies, err := p.graphStore.ListVertices()
	if err != nil {
		return nil, fmt.Errorf("list vertices: %w", err)
	}
	for _, vertex := range verticies {
		node, _, err := p.graphStore.Vertex(vertex)
		if err != nil {
			return nil, fmt.Errorf("get vertex: %w", err)
		}
		out = append(out, node)
	}
	return storage.PeerFilters(filters).Filter(out), nil
}

// ListIDs returns all node IDs in the graph.
func (p *ValidatingPeerStore) ListIDs(ctx context.Context) ([]types.NodeID, error) {
	return p.graphStore.ListVertices()
}

// PutEdge validates the edge and then calls the underlying storage.Peers PutEdge method.
func (p *ValidatingPeerStore) PutEdge(ctx context.Context, edge types.MeshEdge) error {
	if edge.Source == edge.Target {
		return nil
	}
	if !edge.SourceID().IsValid() {
		return fmt.Errorf("%w: %s", errors.ErrInvalidNodeID, edge.SourceID())
	}
	if !edge.TargetID().IsValid() {
		return fmt.Errorf("%w: %s", errors.ErrInvalidNodeID, edge.TargetID())
	}
	return edge.PutInto(ctx, p.graph)
}

// GetEdge returns the edge between the given nodes by first validating the nodes
// and then calling the underlying storage.Peers GetEdge method.
func (p *ValidatingPeerStore) GetEdge(ctx context.Context, source, target types.NodeID) (types.MeshEdge, error) {
	edge, err := p.graph.Edge(source, target)
	if err != nil {
		if errors.Is(err, graph.ErrEdgeNotFound) {
			return types.MeshEdge{}, errors.ErrEdgeNotFound
		}
		return types.MeshEdge{}, fmt.Errorf("get edge: %w", err)
	}
	return types.MeshEdge{MeshEdge: &v1.MeshEdge{
		Source:     edge.Source.GetId(),
		Target:     edge.Target.GetId(),
		Weight:     int32(edge.Properties.Weight),
		Attributes: edge.Properties.Attributes,
	}}, nil
}

// RemoveEdge removes the edge between the given nodes by first validating the nodes
// and then calling the underlying storage.Peers RemoveEdge method.
func (p *ValidatingPeerStore) RemoveEdge(ctx context.Context, from, to types.NodeID) error {
	if !from.IsValid() {
		return fmt.Errorf("%w: %s", errors.ErrInvalidNodeID, from)
	}
	if !to.IsValid() {
		return fmt.Errorf("%w: %s", errors.ErrInvalidNodeID, to)
	}
	err := p.graph.RemoveEdge(from, to)
	if err != nil {
		if err == graph.ErrEdgeNotFound {
			return nil
		}
		return fmt.Errorf("remove edge: %w", err)
	}
	return nil
}

// ValidatingGraphStore wraps a types.PeerGraphStore and automatically performs the
// necessary validation on all operations.
type ValidatingGraphStore struct {
	storage.GraphStore
}

// Subscribe subscribes to node and edge changes from the underlying graph storage.
func (g *ValidatingGraphStore) Subscribe(ctx context.Context, fn storage.PeerSubscribeFunc) (context.CancelFunc, error) {
	return g.GraphStore.Subscribe(ctx, fn)
}

// AddVertex should add the given vertex with the given hash value and vertex properties to the
// graph. If the vertex already exists, it is up to you whether ErrVertexAlreadyExists or no
// error should be returned.
func (g *ValidatingGraphStore) AddVertex(nodeID types.NodeID, node types.MeshNode, props graph.VertexProperties) error {
	if node.GetId() != nodeID.String() {
		return fmt.Errorf("node ID mismatch: %s != %s", node.GetId(), nodeID)
	}
	validated, err := types.ValidateMeshNode(node)
	if err != nil {
		return fmt.Errorf("validate node: %w", err)
	}
	return g.GraphStore.AddVertex(nodeID, validated, props)
}

// Vertex should return the vertex and vertex properties with the given hash value. If the
// vertex doesn't exist, ErrVertexNotFound should be returned.
func (g *ValidatingGraphStore) Vertex(nodeID types.NodeID) (node types.MeshNode, props graph.VertexProperties, err error) {
	if !nodeID.IsValid() {
		err = fmt.Errorf("%w: %s", errors.ErrInvalidNodeID, nodeID)
		return
	}
	return g.GraphStore.Vertex(nodeID)
}

// RemoveVertex should remove the vertex with the given hash value. If the vertex doesn't
// exist, ErrVertexNotFound should be returned. If the vertex has edges to other vertices,
// ErrVertexHasEdges should be returned.
func (g *ValidatingGraphStore) RemoveVertex(nodeID types.NodeID) error {
	if !nodeID.IsValid() {
		return fmt.Errorf("%w: %s", errors.ErrInvalidNodeID, nodeID)
	}
	_, _, err := g.GraphStore.Vertex(nodeID)
	if err != nil {
		return err
	}
	edges, err := g.GraphStore.ListEdges()
	if err != nil {
		return err
	}
	for _, edge := range edges {
		if edge.Source == nodeID || edge.Target == nodeID {
			return graph.ErrVertexHasEdges
		}
	}
	return g.GraphStore.RemoveVertex(nodeID)
}

// AddEdge should add an edge between the vertices with the given source and target hashes.
//
// If either vertex doesn't exit, ErrVertexNotFound should be returned for the respective
// vertex. If the edge already exists, ErrEdgeAlreadyExists should be returned.
func (g *ValidatingGraphStore) AddEdge(sourceNode, targetNode types.NodeID, edge graph.Edge[types.NodeID]) error {
	if sourceNode.IsEmpty() || targetNode.IsEmpty() {
		return errors.ErrEmptyNodeID
	}
	// We diverge from the suggested implementation and only check that one of the nodes
	// exists. This is so joiners can add edges to nodes that are not yet in the graph.
	// If this ends up causing problems, we can change it.
	verticies, err := g.GraphStore.ListVertices()
	if err != nil {
		return err
	}
	edges, err := g.GraphStore.ListEdges()
	if err != nil {
		return err
	}
	var vertexExists bool
	for _, v := range verticies {
		if v == sourceNode || v == targetNode {
			vertexExists = true
			break
		}
	}
	if !vertexExists {
		return graph.ErrVertexNotFound
	}
	for _, edge := range edges {
		if edge.Source == sourceNode && edge.Target == targetNode {
			return graph.ErrEdgeAlreadyExists
		}
	}
	return g.GraphStore.AddEdge(sourceNode, targetNode, edge)
}

// UpdateEdge should update the edge between the given vertices with the data of the given
// Edge instance. If the edge doesn't exist, ErrEdgeNotFound should be returned.
func (g *ValidatingGraphStore) UpdateEdge(sourceNode, targetNode types.NodeID, edge graph.Edge[types.NodeID]) error {
	if sourceNode.IsEmpty() || targetNode.IsEmpty() {
		return errors.ErrEmptyNodeID
	}
	_, err := g.GraphStore.Edge(sourceNode, targetNode)
	if err != nil {
		if errors.Is(err, graph.ErrEdgeNotFound) {
			return err
		}
		if errors.IsKeyNotFound(err) {
			return graph.ErrEdgeNotFound
		}
		return fmt.Errorf("get node edge: %w", err)
	}
	return g.GraphStore.UpdateEdge(sourceNode, targetNode, edge)
}

// Edge should return the edge joining the vertices with the given hash values. It should
// exclusively look for an edge between the source and the target vertex, not vice versa. The
// graph implementation does this for undirected graphs itself.
//
// Note that unlike Graph.Edge, this function is supposed to return an Edge[K], i.e. an edge
// that only contains the vertex hashes instead of the vertices themselves.
//
// If the edge doesn't exist, ErrEdgeNotFound should be returned.
func (g *ValidatingGraphStore) Edge(sourceNode, targetNode types.NodeID) (graph.Edge[types.NodeID], error) {
	if sourceNode.IsEmpty() || targetNode.IsEmpty() {
		return graph.Edge[types.NodeID]{}, errors.ErrEmptyNodeID
	}
	return g.GraphStore.Edge(sourceNode, targetNode)
}

// ValidatingNetworkingStore wraps a storage.Networking and automatically performs the
// necessary validation on all operations.
type ValidatingNetworkingStore struct {
	storage.Networking
}

// PutNetworkACL creates or updates a NetworkACL.
func (v *ValidatingNetworkingStore) PutNetworkACL(ctx context.Context, acl types.NetworkACL) error {
	err := types.ValidateACL(acl)
	if err != nil {
		return fmt.Errorf("%w: %w", errors.ErrInvalidACL, err)
	}
	return v.Networking.PutNetworkACL(ctx, acl)
}

// GetNetworkACL returns a NetworkACL by name.
func (v *ValidatingNetworkingStore) GetNetworkACL(ctx context.Context, name string) (types.NetworkACL, error) {
	if !types.IsValidID(name) {
		return types.NetworkACL{}, fmt.Errorf("%w: %s", errors.ErrInvalidKey, name)
	}
	return v.Networking.GetNetworkACL(ctx, name)
}

// DeleteNetworkACL deletes a NetworkACL by name.
func (v *ValidatingNetworkingStore) DeleteNetworkACL(ctx context.Context, name string) error {
	if !types.IsValidID(name) {
		return fmt.Errorf("%w: %s", errors.ErrInvalidKey, name)
	}
	return v.Networking.DeleteNetworkACL(ctx, name)
}

// PutRoute creates or updates a Route.
func (v *ValidatingNetworkingStore) PutRoute(ctx context.Context, route types.Route) error {
	err := types.ValidateRoute(route)
	if err != nil {
		return fmt.Errorf("%w: %w", errors.ErrInvalidRoute, err)
	}
	return v.Networking.PutRoute(ctx, route)
}

// GetRoute returns a Route by name.
func (v *ValidatingNetworkingStore) GetRoute(ctx context.Context, name string) (types.Route, error) {
	if !types.IsValidID(name) {
		return types.Route{}, fmt.Errorf("%w: %s", errors.ErrInvalidKey, name)
	}
	return v.Networking.GetRoute(ctx, name)
}

// GetRoutesByNode returns a list of Routes for a given Node.
func (v *ValidatingNetworkingStore) GetRoutesByNode(ctx context.Context, nodeID types.NodeID) (types.Routes, error) {
	if !nodeID.IsValid() {
		return nil, fmt.Errorf("%w: %s", errors.ErrInvalidNodeID, nodeID)
	}
	return v.Networking.GetRoutesByNode(ctx, nodeID)
}

// GetRoutesByCIDR returns a list of Routes for a given CIDR.
func (v *ValidatingNetworkingStore) GetRoutesByCIDR(ctx context.Context, cidr netip.Prefix) (types.Routes, error) {
	if !cidr.IsValid() {
		return nil, fmt.Errorf("%w: %s", errors.ErrInvalidPrefix, cidr)
	}
	return v.Networking.GetRoutesByCIDR(ctx, cidr)
}

// DeleteRoute deletes a Route by name.
func (v *ValidatingNetworkingStore) DeleteRoute(ctx context.Context, name string) error {
	if !types.IsValidID(name) {
		return fmt.Errorf("%w: %s", errors.ErrInvalidKey, name)
	}
	return v.Networking.DeleteRoute(ctx, name)
}

// ValidatingRBACStore wraps a storage.RBAC and automatically performs the
// necessary validation on all operations.
type ValidatingRBACStore struct {
	storage.RBAC
}

// PutRole creates or updates a role.
func (v *ValidatingRBACStore) PutRole(ctx context.Context, role types.Role) error {
	if storage.IsSystemRole(role.GetName()) {
		// Allow if the role doesn't exist yet.
		_, err := v.RBAC.GetRole(ctx, role.GetName())
		if err != nil && !errors.IsRoleNotFound(err) {
			return err
		}
		if err == nil {
			return fmt.Errorf("%w %q", errors.ErrIsSystemRole, role.GetName())
		}
	}
	err := role.Validate()
	if err != nil {
		return fmt.Errorf("validate role: %w", err)
	}
	return v.RBAC.PutRole(ctx, role)
}

// GetRole returns a role by name.
func (v *ValidatingRBACStore) GetRole(ctx context.Context, name string) (types.Role, error) {
	if !types.IsValidID(name) {
		return types.Role{}, fmt.Errorf("%w: %s", errors.ErrInvalidKey, name)
	}
	return v.RBAC.GetRole(ctx, name)
}

// DeleteRole deletes a role by name.
func (v *ValidatingRBACStore) DeleteRole(ctx context.Context, name string) error {
	if storage.IsSystemRole(name) {
		return fmt.Errorf("%w %q", errors.ErrIsSystemRole, name)
	}
	if !types.IsValidID(name) {
		return fmt.Errorf("%w: %s", errors.ErrInvalidKey, name)
	}
	return v.RBAC.DeleteRole(ctx, name)
}

// PutRoleBinding creates or updates a rolebinding.
func (v *ValidatingRBACStore) PutRoleBinding(ctx context.Context, rolebinding types.RoleBinding) error {
	if storage.IsSystemRoleBinding(rolebinding.GetName()) {
		// Allow if the rolebinding doesn't exist yet.
		_, err := v.RBAC.GetRoleBinding(ctx, rolebinding.GetName())
		if err != nil && !errors.IsRoleBindingNotFound(err) {
			return err
		}
		if err == nil {
			return fmt.Errorf("%w %q", errors.ErrIsSystemRoleBinding, rolebinding.GetName())
		}
	}
	err := rolebinding.Validate()
	if err != nil {
		return fmt.Errorf("validate rolebinding: %w", err)
	}
	return v.RBAC.PutRoleBinding(ctx, rolebinding)
}

// GetRoleBinding returns a rolebinding by name.
func (v *ValidatingRBACStore) GetRoleBinding(ctx context.Context, name string) (types.RoleBinding, error) {
	if !types.IsValidID(name) {
		return types.RoleBinding{}, fmt.Errorf("%w: %s", errors.ErrInvalidKey, name)
	}
	return v.RBAC.GetRoleBinding(ctx, name)
}

// DeleteRoleBinding deletes a rolebinding by name.
func (v *ValidatingRBACStore) DeleteRoleBinding(ctx context.Context, name string) error {
	if storage.IsSystemRoleBinding(name) {
		return fmt.Errorf("%w %q", errors.ErrIsSystemRoleBinding, name)
	}
	if !types.IsValidID(name) {
		return fmt.Errorf("%w: %s", errors.ErrInvalidKey, name)
	}
	return v.RBAC.DeleteRoleBinding(ctx, name)
}

// PutGroup creates or updates a group.
func (v *ValidatingRBACStore) PutGroup(ctx context.Context, group types.Group) error {
	err := group.Validate()
	if err != nil {
		return fmt.Errorf("validate group: %w", err)
	}
	return v.RBAC.PutGroup(ctx, group)
}

// GetGroup returns a group by name.
func (v *ValidatingRBACStore) GetGroup(ctx context.Context, name string) (types.Group, error) {
	if !types.IsValidID(name) {
		return types.Group{}, fmt.Errorf("%w: %s", errors.ErrInvalidKey, name)
	}
	return v.RBAC.GetGroup(ctx, name)
}

// DeleteGroup deletes a group by name.
func (v *ValidatingRBACStore) DeleteGroup(ctx context.Context, name string) error {
	if storage.IsSystemGroup(name) {
		return fmt.Errorf("%w %q", errors.ErrIsSystemGroup, name)
	}
	if !types.IsValidID(name) {
		return fmt.Errorf("%w: %s", errors.ErrInvalidKey, name)
	}
	return v.RBAC.DeleteGroup(ctx, name)
}

// ListNodeRoles returns a list of all roles for a node.
func (v *ValidatingRBACStore) ListNodeRoles(ctx context.Context, nodeID types.NodeID) (types.RolesList, error) {
	if !nodeID.IsValid() {
		return nil, fmt.Errorf("%w: %s", errors.ErrInvalidNodeID, nodeID)
	}
	return v.RBAC.ListNodeRoles(ctx, nodeID)
}

// ListUserRoles returns a list of all roles for a user.
func (v *ValidatingRBACStore) ListUserRoles(ctx context.Context, userID types.NodeID) (types.RolesList, error) {
	if !userID.IsValid() {
		return nil, fmt.Errorf("%w: %s", errors.ErrInvalidNodeID, userID)
	}
	return v.RBAC.ListUserRoles(ctx, userID)
}
