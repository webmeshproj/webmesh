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

	"github.com/dominikbraun/graph"

	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// GraphStore is a storage interface for graph data.
type GraphStore interface {
	// PeerGraphStore is a storage interface for peer graph data.
	types.PeerGraphStore

	// Subscribe subscribes to changes to nodes and edges.
	Subscribe(ctx context.Context, fn PeerSubscribeFunc) (context.CancelFunc, error)
}

// NewGraphWithStore creates a new Graph instance with the given graph storage implementation.
func NewGraphWithStore(store GraphStore) types.PeerGraph {
	return graph.NewWithStore(graphHasher, store)
}

// graphHasher is the hash key function for the graph.
func graphHasher(n types.MeshNode) types.NodeID { return types.NodeID(n.GetId()) }
