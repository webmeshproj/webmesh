//go:build !wasm

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

package nutsdb

import (
	"os"
	"testing"

	"github.com/webmeshproj/webmesh/pkg/storage"
)

func TestDiskStorage(t *testing.T) {
	t.Skip("skipping disk storage test")

	dir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatalf("failed to remove temp dir: %v", err)
		}
	})
	st, err := newDiskStorage(dir)
	if err != nil {
		t.Fatalf("failed to create in-memory storage: %v", err)
	}
	defer st.Close()
	storage.RunDualStorageConformance(t, st)
}
