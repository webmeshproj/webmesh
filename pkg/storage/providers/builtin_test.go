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

package providers

import (
	"context"
	"os"
	"testing"

	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb"
	"github.com/webmeshproj/webmesh/pkg/storage/providers/backends/badgerdb"
	"github.com/webmeshproj/webmesh/pkg/storage/testutil"
)

func TestBuiltinDataStoreConformance(t *testing.T) {
	testutil.TestMeshDataStoreConformance(t, func(t *testing.T) storage.MeshDataStore {
		db := meshdb.NewTestDB()
		t.Cleanup(func() {
			_ = db.Close()
		})
		return db
	})
	testutil.TestPeerStorageConformance(t, func(t *testing.T) storage.Peers {
		db := meshdb.NewTestDB()
		t.Cleanup(func() {
			_ = db.Close()
		})
		return db.Peers()
	})
}

func TestBadgerStoreConformance(t *testing.T) {
	st, err := badgerdb.NewInMemory(badgerdb.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	testutil.TestDualStorageConformance(context.Background(), t, st)
	dir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	st, err = badgerdb.New(badgerdb.Options{
		DiskPath: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	testutil.TestDualStorageConformance(context.Background(), t, st)
}
