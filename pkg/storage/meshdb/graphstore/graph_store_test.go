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

package graphstore

import (
	"testing"

	"github.com/webmeshproj/webmesh/pkg/storage/providers/backends/badgerdb"
	"github.com/webmeshproj/webmesh/pkg/storage/testutil"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

func TestGraphStore(t *testing.T) {
	t.Parallel()
	testutil.TestPeerGraphstoreConformance(t, func(t *testing.T) types.PeerGraphStore {
		memdb, err := badgerdb.NewInMemory(badgerdb.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = memdb.Close() })
		return &GraphStore{MeshStorage: memdb}
	})
}
