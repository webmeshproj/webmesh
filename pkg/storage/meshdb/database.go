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
	"fmt"
	"io"

	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb/graph"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb/networking"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb/peers"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb/rbac"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb/state"
	"github.com/webmeshproj/webmesh/pkg/storage/providers/backends/badgerdb"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// New returns a new storage.Database instance using the given underlying MeshStorage.
func New(store storage.MeshStorage) storage.MeshDB {
	return &database{
		peers:      peers.New(store),
		graph:      types.NewGraphWithStore(graph.NewGraphStore(store)),
		rbac:       rbac.New(store),
		meshState:  state.New(store),
		networking: networking.New(store),
	}
}

// MeshDBCloser is a storage.MeshDB that can be closed.
type MeshDBCloser interface {
	storage.MeshDB
	io.Closer
}

// NewTestDB returns a new in-memory storage.Database instance for testing.
func NewTestDB() (MeshDBCloser, error) {
	memdb, err := badgerdb.NewInMemory(badgerdb.Options{})
	if err != nil {
		return nil, fmt.Errorf("create in-memory database: %w", err)
	}
	return &TestDB{
		MeshDB: New(memdb),
		Closer: memdb,
	}, nil
}

type TestDB struct {
	storage.MeshDB
	io.Closer
}

type database struct {
	peers      storage.Peers
	graph      types.PeerGraph
	rbac       storage.RBAC
	meshState  storage.MeshState
	networking storage.Networking
}

func (d *database) Peers() storage.Peers {
	return d.peers
}

func (d *database) PeerGraph() types.PeerGraph {
	return d.graph
}

func (d *database) RBAC() storage.RBAC {
	return d.rbac
}

func (d *database) MeshState() storage.MeshState {
	return d.meshState
}

func (d *database) Networking() storage.Networking {
	return d.networking
}
