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
	"io"

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
	// Graph returns the graph of nodes.
	Graph() types.PeerGraph
	// Put creates or updates a node.
	Put(ctx context.Context, n *v1.MeshNode) error
	// Get gets a node by ID.
	Get(ctx context.Context, id string) (types.MeshNode, error)
	// GetByPubKey gets a node by their public key.
	GetByPubKey(ctx context.Context, key crypto.PublicKey) (types.MeshNode, error)
	// Delete deletes a node.
	Delete(ctx context.Context, id string) error
	// List lists all nodes.
	List(ctx context.Context) ([]types.MeshNode, error)
	// ListIDs lists all node IDs.
	ListIDs(ctx context.Context) ([]string, error)
	// ListPublicNodes lists all public nodes.
	ListPublicNodes(ctx context.Context) ([]types.MeshNode, error)
	// ListByZoneID lists all nodes in a zone.
	ListByZoneID(ctx context.Context, zoneID string) ([]types.MeshNode, error)
	// ListByFeature lists all nodes with a given feature.
	ListByFeature(ctx context.Context, feature v1.Feature) ([]types.MeshNode, error)
	// Subscribe subscribes to node changes.
	Subscribe(ctx context.Context, fn PeerSubscribeFunc) (context.CancelFunc, error)
	// AddEdge adds an edge between two nodes.
	PutEdge(ctx context.Context, edge *v1.MeshEdge) error
	// RemoveEdge removes an edge between two nodes.
	RemoveEdge(ctx context.Context, from, to string) error
	// DrawDOTGraph draws the graph of nodes to the given Writer.
	DrawDOTGraph(ctx context.Context, w io.Writer) error
}
