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

package badgerdb

import (
	"context"
	"os"
	"testing"

	"github.com/webmeshproj/webmesh/pkg/storage/testutil"
)

var BadgerTestDebug = false

func init() {
	if os.Getenv("BADGER_TEST_DEBUG") == "true" {
		BadgerTestDebug = true
	}
}

func TestInMemoryBadgerStorage(t *testing.T) {
	st, err := NewInMemory(Options{
		Debug: BadgerTestDebug,
	})
	if err != nil {
		t.Fatalf("failed to create in-memory storage: %v", err)
	}
	defer st.Close()
	testutil.TestDualStorageConformance(context.Background(), t, st)
}

func TestDiskBadgerStorage(t *testing.T) {
	tmp, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() {
		os.RemoveAll(tmp)
	})
	st, err := New(Options{
		DiskPath: tmp,
		Debug:    BadgerTestDebug,
	})
	if err != nil {
		t.Fatalf("failed to create disk storage: %v", err)
	}
	defer st.Close()
	testutil.TestDualStorageConformance(context.Background(), t, st)
}
