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
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// NewMeshDBFunc is a function that creates a new MeshDB implementation.
type NewMeshDBFunc func(t *testing.T) (storage.MeshDB, types.PeerGraphStore)

// TestMeshDBConformance is a helper for running all database conformance
// tests against a MeshDB implementation.
func TestMeshDBConformance(t *testing.T, builder NewMeshDBFunc) {
	t.Run("MeshDBConformance", func(t *testing.T) {
		TestPeerGraphstoreConformance(t, func(t *testing.T) types.PeerGraphStore {
			_, graph := builder(t)
			return graph
		})
		TestMeshStateStorageConformance(t, func(t *testing.T) storage.MeshState {
			db, _ := builder(t)
			return db.MeshState()
		})
		TestRBACStorageConformance(t, func(t *testing.T) storage.RBAC {
			db, _ := builder(t)
			return db.RBAC()
		})
		TestPeerStorageConformance(t, func(t *testing.T) storage.Peers {
			db, _ := builder(t)
			return db.Peers()
		})
		TestNetworkingStorageConformance(t, func(t *testing.T) storage.Networking {
			db, _ := builder(t)
			return db.Networking()
		})
	})
}
