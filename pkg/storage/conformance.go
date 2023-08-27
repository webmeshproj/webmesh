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
	"strings"
	"testing"
)

// RunRaftStorageConformance tests that the RaftStorage interface is implemented correctly.
func RunRaftStorageConformance(t *testing.T, raftStorage RaftStorage) {
	t.Helper()

	t.Run("RaftLogStore", func(t *testing.T) {})

	t.Run("RaftStableStore", func(t *testing.T) {})
}

// RunMeshStorageConformance tests that the MeshStorage interface is implemented correctly.
func RunMeshStorageConformance(t *testing.T, meshStorage MeshStorage) {
	t.Helper()
	ctx := context.Background()

	t.Run("GetValue", func(t *testing.T) {
		// Try to get a non-existent key and ensure it returns ErrKeyNotFound.
		_, err := meshStorage.GetValue(ctx, "non-existent-key")
		if !IsKeyNotFoundError(err) {
			t.Errorf("expected ErrKeyNotFound, got %v", err)
		}
		// Put a key and make sure it survives a round trip.
		key, value := "key", "value"
		if err := meshStorage.PutValue(ctx, key, value, 0); err != nil {
			t.Fatalf("failed to put key: %v", err)
		}
		got, err := meshStorage.GetValue(ctx, key)
		if err != nil {
			t.Fatalf("failed to get key: %v", err)
		}
		if got != value {
			t.Errorf("expected %q, got %q", value, got)
		}
	})

	t.Run("PutValue", func(t *testing.T) {
		// Pretty simple, just put a key and make sure it survives a round trip.
		key, value := "key", "value"
		if err := meshStorage.PutValue(ctx, key, value, 0); err != nil {
			t.Fatalf("failed to put key: %v", err)
		}
		got, err := meshStorage.GetValue(ctx, key)
		if err != nil {
			t.Fatalf("failed to get key: %v", err)
		}
		if got != value {
			t.Errorf("expected %q, got %q", value, got)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		// Delete should never error, but it should also work
		// if the key does in fact exist.
		key := "key"
		if err := meshStorage.Delete(ctx, key); err != nil {
			t.Fatalf("failed to delete key: %v", err)
		}
		// Try to get a non-existent key and ensure it returns ErrKeyNotFound.
		_, err := meshStorage.GetValue(ctx, key)
		if !IsKeyNotFoundError(err) {
			t.Errorf("expected ErrKeyNotFound, got %v", err)
		}
		// Put a key and make sure it survives a round trip, and then delete it.
		value := "value"
		if err := meshStorage.PutValue(ctx, key, value, 0); err != nil {
			t.Fatalf("failed to put key: %v", err)
		}
		if err := meshStorage.Delete(ctx, key); err != nil {
			t.Fatalf("failed to delete key: %v", err)
		}
		_, err = meshStorage.GetValue(ctx, key)
		if !IsKeyNotFoundError(err) {
			t.Errorf("expected ErrKeyNotFound, got %v", err)
		}
	})

	t.Run("List", func(t *testing.T) {
		// Place a few keys and make sure we get the full list of them back
		// when we list them.
		kv := map[string]string{
			"key1": "value1",
			"key2": "value2",
			"key3": "value3",
		}
		for key, value := range kv {
			if err := meshStorage.PutValue(ctx, key, value, 0); err != nil {
				t.Fatalf("failed to put key: %v", err)
			}
		}
		keysl, err := meshStorage.List(ctx, "")
		if err != nil {
			t.Fatalf("failed to list keys: %v", err)
		}
		if len(keysl) != len(kv) {
			t.Errorf("expected %d keys, got %d", len(kv), len(keysl))
		}
		keys := map[string]struct{}{
			"key1": {},
			"key2": {},
			"key3": {},
		}
		for key := range keys {
			if _, ok := kv[key]; !ok {
				t.Errorf("unexpected key %q", key)
			}
		}
		// Make sure the same works for a specific prefix
		kv = map[string]string{
			"prefix1/key1": "value1",
			"prefix1/key2": "value2",
		}
		for key, value := range kv {
			if err := meshStorage.PutValue(ctx, key, value, 0); err != nil {
				t.Fatalf("failed to put key: %v", err)
			}
		}
		keysl, err = meshStorage.List(ctx, "prefix1/")
		if err != nil {
			t.Fatalf("failed to list keys: %v", err)
		}
		if len(keysl) != len(kv) {
			t.Errorf("expected %d keys, got %d", len(kv), len(keysl))
		}
		keys = map[string]struct{}{
			"prefix1/key1": {},
			"prefix1/key2": {},
		}
		for key := range keys {
			if _, ok := kv[key]; !ok {
				t.Errorf("unexpected key %q", key)
			}
		}
	})

	t.Run("IterPrefix", func(t *testing.T) {
		// We'll place a few keys and make sure our iterator is called
		// for each of them.
		kv := map[string]string{
			"IterPrefix1/key1": "value1",
			"IterPrefix1/key2": "value2",
			"IterPrefix2/key1": "value1",
			"IterPrefix2/key2": "value2",
		}
		for key, value := range kv {
			if err := meshStorage.PutValue(ctx, key, value, 0); err != nil {
				t.Fatalf("failed to put key: %v", err)
			}
		}
		seen := map[string]struct{}{}
		err := meshStorage.IterPrefix(ctx, "IterPrefix1/", func(key, value string) error {
			seen[key] = struct{}{}
			return nil
		})
		if err != nil {
			t.Fatalf("failed to iterate over keys: %v", err)
		}
		if len(seen) != 2 {
			t.Errorf("expected to see 2 keys, got %d", len(seen))
		}
		for key := range seen {
			if !strings.HasPrefix(key, "IterPrefix1/") {
				t.Errorf("unexpected key %q", key)
			}
		}
	})

	t.Run("Subscribe", func(t *testing.T) {
		// Subscribe to a prefix and make sure out callback is called
		// when a key is added, updated, and deleted.
		kv := map[string]string{
			"Subscribe/key1": "value1",
			"Subscribe/key2": "value2",
		}
		seen := map[string]struct{}{}
		var count int
		cancel, err := meshStorage.Subscribe(ctx, "Subscribe/", func(key, value string) {
			t.Logf("key %q was %q", key, value)
			count++
			seen[key] = struct{}{}
		})
		if err != nil {
			t.Fatalf("failed to subscribe: %v", err)
		}
		defer cancel()
		for key, value := range kv {
			if err := meshStorage.PutValue(ctx, key, value, 0); err != nil {
				t.Fatalf("failed to put key: %v", err)
			}
		}
		if count != len(kv) {
			t.Errorf("expected %d calls, got %d", len(kv), count)
		}
		for key := range kv {
			if _, ok := seen[key]; !ok {
				t.Errorf("expected to see key %q", key)
			}
		}
	})

	t.Run("Snapshot", func(t *testing.T) {})

	t.Run("Restore", func(t *testing.T) {})
}

// RunDualStorageConformance tests that the DualStorage interface is implemented correctly.
func RunDualStorageConformance(t *testing.T, dualStorage DualStorage) {
	t.Helper()
	RunRaftStorageConformance(t, dualStorage)
	RunMeshStorageConformance(t, dualStorage)
}
