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
	"context"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// NodesPrefix is where nodes are stored in the database.
// nodes are indexed by their ID in the format /registry/nodes/<id>.
var NodesPrefix = types.RegistryPrefix.ForString("nodes")

// EdgesPrefix is where edges are stored in the database.
// edges are indexed by their source and target node IDs
// in the format /registry/edges/<source>/<target>.
var EdgesPrefix = types.RegistryPrefix.ForString("edges")

// PeerSubscribeFunc is a function that can be used to subscribe to peer changes.
// The function is called with multiple peers when the change reflects a new edge
// being added or removed. The function is called with a single peer when the
// change reflects a node being added or removed.
type PeerSubscribeFunc func([]types.MeshNode)

// Peers is the peers interface.
type Peers interface {
	// Put creates or updates a node.
	Put(ctx context.Context, n types.MeshNode) error
	// Get gets a node by ID.
	Get(ctx context.Context, id types.NodeID) (types.MeshNode, error)
	// GetByPubKey gets a node by their public key.
	GetByPubKey(ctx context.Context, key crypto.PublicKey) (types.MeshNode, error)
	// Delete deletes a node.
	Delete(ctx context.Context, id types.NodeID) error
	// List lists all nodes.
	List(ctx context.Context, filters ...PeerFilter) ([]types.MeshNode, error)
	// ListIDs lists all node IDs.
	ListIDs(ctx context.Context) ([]types.NodeID, error)
	// Subscribe subscribes to node changes.
	Subscribe(ctx context.Context, fn PeerSubscribeFunc) (context.CancelFunc, error)
	// AddEdge adds an edge between two nodes.
	PutEdge(ctx context.Context, edge types.MeshEdge) error
	// GetEdge gets an edge between two nodes.
	GetEdge(ctx context.Context, from, to types.NodeID) (types.MeshEdge, error)
	// RemoveEdge removes an edge between two nodes.
	RemoveEdge(ctx context.Context, from, to types.NodeID) error
}

// PeerFilter is a filter for nodes.
type PeerFilter func(types.MeshNode) bool

// PeerFilters is a list of filters.
type PeerFilters []PeerFilter

// Filter filters a list of nodes.
func (f PeerFilters) Filter(nodes []types.MeshNode) []types.MeshNode {
	var filtered []types.MeshNode
	for _, node := range nodes {
		if f.Match(node) {
			filtered = append(filtered, node)
		}
	}
	return filtered
}

// Match returns true if the node matches all filters.
func (f PeerFilters) Match(node types.MeshNode) bool {
	for _, filter := range f {
		if !filter(node) {
			return false
		}
	}
	return true
}

// FeatureFilter returns a new filter that matches nodes with a given feature.
func FeatureFilter(feature v1.Feature) PeerFilter {
	return func(node types.MeshNode) bool {
		return node.HasFeature(feature)
	}
}

// IsPublicFilter returns a new filter that matches public nodes.
func IsPublicFilter() PeerFilter {
	return func(node types.MeshNode) bool {
		return node.GetPrimaryEndpoint() != ""
	}
}

// ZoneIDFilter returns a new filter that matches nodes in a given zone.
func ZoneIDFilter(zoneID string) PeerFilter {
	return func(node types.MeshNode) bool {
		return node.GetZoneAwarenessID() == zoneID
	}
}

// NotNodeIDFilter returns a new filter that matches nodes that are not a given node ID.
func NotNodeIDFilter(nodeID types.NodeID) PeerFilter {
	return func(node types.MeshNode) bool {
		return node.NodeID() != nodeID
	}
}
