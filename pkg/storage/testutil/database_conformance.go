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

package testutil

import (
	"testing"

	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// NewMeshDataStoreFunc is a function that creates a new MeshDataStore implementation.
type NewMeshDataStoreFunc func(t *testing.T) storage.MeshDataStore

// TestMeshDataStoreConformance is a helper for running all database conformance
// tests against a MeshDataStore implementation.
func TestMeshDataStoreConformance(t *testing.T, builder NewMeshDataStoreFunc) {
	t.Run("MeshDBConformance", func(t *testing.T) {
		TestPeerGraphstoreConformance(t, func(t *testing.T) types.PeerGraphStore {
			db := meshdb.New(builder(t))
			return db.GraphStore()
		})
		TestMeshStateStorageConformance(t, func(t *testing.T) storage.MeshState {
			db := meshdb.New(builder(t))
			return db.MeshState()
		})
		TestRBACStorageConformance(t, func(t *testing.T) storage.RBAC {
			db := meshdb.New(builder(t))
			return db.RBAC()
		})
		TestNetworkingStorageConformance(t, func(t *testing.T) storage.Networking {
			db := meshdb.New(builder(t))
			return db.Networking()
		})
	})
}
