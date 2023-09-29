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
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// PeerFilterFunc is a function that can be used to filter responses returned by a resolver.
type PeerFilterFunc func(types.MeshNode) bool

// PeerResolver provides facilities for creating various transport.Resolver instances.
type PeerResolver interface {
	// NodeIDResolver returns a resolver that resolves node addresses by node ID.
	NodeIDResolver() transport.NodeIDResolver
	// FeatureResolver returns a resolver that resolves node addresses by feature.
	FeatureResolver(filterFn ...PeerFilterFunc) transport.FeatureResolver
}

// Peers is the peers interface.
type Peers interface {
	// Resolver returns a resolver backed by the storage
	// of this instance.
	Resolver() PeerResolver
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
	// AddEdge adds an edge between two nodes.
	PutEdge(ctx context.Context, edge *v1.MeshEdge) error
	// RemoveEdge removes an edge between two nodes.
	RemoveEdge(ctx context.Context, from, to string) error
	// DrawDOTGraph draws the graph of nodes to the given Writer.
	DrawDOTGraph(ctx context.Context, w io.Writer) error
}
