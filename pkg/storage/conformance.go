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
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/proto"
)

// RunRaftStorageConformance tests that the RaftStorage interface is implemented correctly.
func RunRaftStorageConformance(t *testing.T, raftStorage RaftStorage) {
	t.Helper()

	t.Run("RaftStableStore", func(t *testing.T) {
		t.Run("Set", func(t *testing.T) {
			// Should be able to set a key and then get it back.
			key, value := "key", "value"
			if err := raftStorage.Set([]byte(key), []byte(value)); err != nil {
				t.Fatalf("failed to set key: %v", err)
			}
			got, err := raftStorage.Get([]byte(key))
			if err != nil {
				t.Fatalf("failed to get key: %v", err)
			}
			if string(got) != value {
				t.Errorf("expected %q, got %q", value, got)
			}
			// We should be able to change the value of a key.
			value = "new-value"
			if err := raftStorage.Set([]byte(key), []byte(value)); err != nil {
				t.Fatalf("failed to set key: %v", err)
			}
			got, err = raftStorage.Get([]byte(key))
			if err != nil {
				t.Fatalf("failed to get key: %v", err)
			}
			if string(got) != value {
				t.Errorf("expected %q, got %q", value, got)
			}
		})

		t.Run("Get", func(t *testing.T) {
			// Same as the Set test.
			key, value := "key", "value"
			if err := raftStorage.Set([]byte(key), []byte(value)); err != nil {
				t.Fatalf("failed to set key: %v", err)
			}
			got, err := raftStorage.Get([]byte(key))
			if err != nil {
				t.Fatalf("failed to get key: %v", err)
			}
			if string(got) != value {
				t.Errorf("expected %q, got %q", value, got)
			}
			// A non-existant key should not error and return an empty value.
			got, err = raftStorage.Get([]byte("non-existent-key"))
			if err != nil {
				t.Fatalf("failed to get key: %v", err)
			}
			if len(got) != 0 {
				t.Errorf("expected empty value, got %q", got)
			}
		})

		t.Run("SetUint64", func(t *testing.T) {
			key := []byte("uint64-key")
			// Should be able to set a uint64 and then get it back.
			value := uint64(1234567890)
			if err := raftStorage.SetUint64(key, value); err != nil {
				t.Fatalf("failed to set uint64: %v", err)
			}
			got, err := raftStorage.GetUint64(key)
			if err != nil {
				t.Fatalf("failed to get uint64: %v", err)
			}
			if got != value {
				t.Errorf("expected %d, got %d", value, got)
			}
			// We should be able to change the value of a uint64.
			value = 9876543210
			if err := raftStorage.SetUint64(key, value); err != nil {
				t.Fatalf("failed to set uint64: %v", err)
			}
			got, err = raftStorage.GetUint64(key)
			if err != nil {
				t.Fatalf("failed to get uint64: %v", err)
			}
			if got != value {
				t.Errorf("expected %d, got %d", value, got)
			}
		})

		t.Run("GetUint64", func(t *testing.T) {
			// Same as the SetUint64 test.
			key := []byte("uint64-key")
			value := uint64(1234567890)
			if err := raftStorage.SetUint64(key, value); err != nil {
				t.Fatalf("failed to set uint64: %v", err)
			}
			got, err := raftStorage.GetUint64(key)
			if err != nil {
				t.Fatalf("failed to get uint64: %v", err)
			}
			if got != value {
				t.Errorf("expected %d, got %d", value, got)
			}
			// A non-existant key should not error and return 0.
			got, err = raftStorage.GetUint64([]byte("non-existent-key"))
			if err != nil {
				t.Fatalf("failed to get uint64: %v", err)
			}
			if got != 0 {
				t.Errorf("expected 0, got %d", got)
			}
		})
	})

	t.Run("RaftLogStore", func(t *testing.T) {
		t.Run("FirstIndex", func(t *testing.T) {
			// First Index should return 0 if there are no entries.
			got, err := raftStorage.FirstIndex()
			if err != nil {
				t.Fatalf("failed to get first index: %v", err)
			}
			if got != 0 {
				t.Errorf("expected 0, got %d", got)
			}
			// Store a log and it should become the first index
			if err := raftStorage.StoreLog(&raft.Log{
				Index:      1,
				Term:       1,
				Type:       raft.LogCommand,
				AppendedAt: time.Now(),
			}); err != nil {
				t.Fatalf("failed to store log: %v", err)
			}
			got, err = raftStorage.FirstIndex()
			if err != nil {
				t.Fatalf("failed to get first index: %v", err)
			}
			if got != 1 {
				t.Errorf("expected 1, got %d", got)
			}
			// Store another log and the first index should not change.
			if err := raftStorage.StoreLog(&raft.Log{
				Index:      2,
				Term:       1,
				Type:       raft.LogCommand,
				AppendedAt: time.Now(),
			}); err != nil {
				t.Fatalf("failed to store log: %v", err)
			}
			got, err = raftStorage.FirstIndex()
			if err != nil {
				t.Fatalf("failed to get first index: %v", err)
			}
			if got != 1 {
				t.Errorf("expected 1, got %d", got)
			}
		})

		t.Run("LastIndex", func(t *testing.T) {
			// Last Index should always return the last index.
			// We are assuming the state from the FirstIndex test.
			got, err := raftStorage.LastIndex()
			if err != nil {
				t.Fatalf("failed to get last index: %v", err)
			}
			if got != 2 {
				t.Errorf("expected 2, got %d", got)
			}
			// Store a log and it should become the last index
			if err := raftStorage.StoreLog(&raft.Log{
				Index:      3,
				Term:       1,
				Type:       raft.LogCommand,
				AppendedAt: time.Now(),
			}); err != nil {
				t.Fatalf("failed to store log: %v", err)
			}
			got, err = raftStorage.LastIndex()
			if err != nil {
				t.Fatalf("failed to get last index: %v", err)
			}
			if got != 3 {
				t.Errorf("expected 3, got %d", got)
			}
		})

		t.Run("GetLog", func(t *testing.T) {
			// Place a log with some data and make sure we can get it back.
			log := &raft.Log{
				Index:      4,
				Term:       1,
				Type:       raft.LogCommand,
				Data:       []byte("data"),
				AppendedAt: time.Now(),
			}
			if err := raftStorage.StoreLog(log); err != nil {
				t.Fatalf("failed to store log: %v", err)
			}
			err := raftStorage.GetLog(log.Index, log)
			if err != nil {
				t.Fatalf("failed to get log: %v", err)
			}
			if log.Index != 4 {
				t.Errorf("expected 4, got %d", log.Index)
			}
			if log.Term != 1 {
				t.Errorf("expected 1, got %d", log.Term)
			}
			if log.Type != raft.LogCommand {
				t.Errorf("expected %d, got %d", raft.LogCommand, log.Type)
			}
			if string(log.Data) != "data" {
				t.Errorf("expected %q, got %q", "data", string(log.Data))
			}
			// A non-existant log should return raft.ErrLogNotFound
			err = raftStorage.GetLog(5, log)
			if err != raft.ErrLogNotFound {
				t.Errorf("expected %v, got %v", raft.ErrLogNotFound, err)
			}
		})

		t.Run("StoreLog", func(t *testing.T) {
			// Same as the GetLog test.
			log := &raft.Log{
				Index:      5,
				Term:       1,
				Type:       raft.LogCommand,
				Data:       []byte("data"),
				AppendedAt: time.Now(),
			}
			if err := raftStorage.StoreLog(log); err != nil {
				t.Fatalf("failed to store log: %v", err)
			}
			err := raftStorage.GetLog(log.Index, log)
			if err != nil {
				t.Fatalf("failed to get log: %v", err)
			}
			if log.Index != 5 {
				t.Errorf("expected 5, got %d", log.Index)
			}
			if log.Term != 1 {
				t.Errorf("expected 1, got %d", log.Term)
			}
			if log.Type != raft.LogCommand {
				t.Errorf("expected %d, got %d", raft.LogCommand, log.Type)
			}
			if string(log.Data) != "data" {
				t.Errorf("expected %q, got %q", "data", string(log.Data))
			}
		})

		t.Run("StoreLogs", func(t *testing.T) {
			// Same as the StoreLog test, but with multiple logs.
			logs := []*raft.Log{
				{
					Index:      6,
					Term:       1,
					Type:       raft.LogCommand,
					Data:       []byte("data1"),
					AppendedAt: time.Now(),
				},
				{
					Index:      7,
					Term:       1,
					Type:       raft.LogCommand,
					Data:       []byte("data2"),
					AppendedAt: time.Now(),
				},
			}
			if err := raftStorage.StoreLogs(logs); err != nil {
				t.Fatalf("failed to store logs: %v", err)
			}
			// Get each log and make sure it matches.
			var log raft.Log
			if err := raftStorage.GetLog(6, &log); err != nil {
				t.Fatalf("failed to get log: %v", err)
			}
			if log.Index != 6 {
				t.Errorf("expected 6, got %d", log.Index)
			}
			if log.Term != 1 {
				t.Errorf("expected 1, got %d", log.Term)
			}
			if log.Type != raft.LogCommand {
				t.Errorf("expected %d, got %d", raft.LogCommand, log.Type)
			}
			if string(log.Data) != "data1" {
				t.Errorf("expected %q, got %q", "data1", string(log.Data))
			}
			if err := raftStorage.GetLog(7, &log); err != nil {
				t.Fatalf("failed to get log: %v", err)
			}
			if log.Index != 7 {
				t.Errorf("expected 7, got %d", log.Index)
			}
			if log.Term != 1 {
				t.Errorf("expected 1, got %d", log.Term)
			}
			if log.Type != raft.LogCommand {
				t.Errorf("expected %d, got %d", raft.LogCommand, log.Type)
			}
			if string(log.Data) != "data2" {
				t.Errorf("expected %q, got %q", "data2", string(log.Data))
			}
		})

		t.Run("DeleteRange", func(t *testing.T) {
			// We should be able to delete all of the logs we created
			// in this test. It should work with an inclusive range
			if err := raftStorage.DeleteRange(1, 7); err != nil {
				t.Fatalf("failed to delete range: %v", err)
			}
			// All the logs should be gone
			for i := 1; i <= 7; i++ {
				err := raftStorage.GetLog(uint64(i), &raft.Log{})
				if err != raft.ErrLogNotFound {
					t.Errorf("expected %v, got %v", raft.ErrLogNotFound, err)
				}
			}
		})
	})

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
		// Clean up
		if err := meshStorage.Delete(ctx, key); err != nil {
			t.Fatalf("failed to delete key: %v", err)
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
		// Clean up
		if err := meshStorage.Delete(ctx, key); err != nil {
			t.Fatalf("failed to delete key: %v", err)
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
		// Clean up
		for key := range kv {
			if err := meshStorage.Delete(ctx, key); err != nil {
				t.Fatalf("failed to delete key: %v", err)
			}
		}
		for _, key := range []string{"key1", "key2", "key3"} {
			if err := meshStorage.Delete(ctx, key); err != nil {
				t.Fatalf("failed to delete key: %v", err)
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
		// Clean up
		for key := range kv {
			if err := meshStorage.Delete(ctx, key); err != nil {
				t.Fatalf("failed to delete key: %v", err)
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
		// Clean up
		for key := range kv {
			if err := meshStorage.Delete(ctx, key); err != nil {
				t.Fatalf("failed to delete key: %v", err)
			}
		}
	})

	// We will use the same snapshot for the Snapshot and Restore tests
	var snapshot io.Reader
	snapshotKV := map[string]string{
		"Snapshot/key1": "value1",
		"Snapshot/key2": "value2",
	}

	t.Run("Snapshot", func(t *testing.T) {
		// Place a few keys and make sure a snapshot conforms to our expectations.
		for key, value := range snapshotKV {
			if err := meshStorage.PutValue(ctx, key, value, 0); err != nil {
				t.Fatalf("failed to put key: %v", err)
			}
		}
		var err error
		snapshot, err = meshStorage.Snapshot(ctx)
		if err != nil {
			t.Fatalf("failed to get snapshot: %v", err)
		}
		// Unmarshal the snapshot
		var snap v1.RaftSnapshot
		var buf bytes.Buffer
		tee := io.TeeReader(snapshot, &buf)
		data, err := io.ReadAll(tee)
		// Reset the snapshot reader for the Restore test
		snapshot = &buf
		if err != nil {
			t.Fatalf("failed to read snapshot: %v", err)
		}
		if err := proto.Unmarshal(data, &snap); err != nil {
			t.Fatalf("failed to unmarshal snapshot: %v", err)
		}
		// Make sure the snapshot has the correct keys
		if len(snap.Kv) != len(snapshotKV) {
			t.Errorf("expected %d keys, got %d", len(snapshotKV), len(snap.Kv))
		}
		for _, keyval := range snap.Kv {
			if _, ok := snapshotKV[keyval.Key]; !ok {
				t.Errorf("unexpected key %q", keyval.Key)
			}
		}
		// Make sure the snapshot items have the correct data
		for _, keyval := range snap.Kv {
			if keyval.Value != snapshotKV[keyval.Key] {
				t.Errorf("expected %q, got %q", snapshotKV[keyval.Key], keyval.Value)
			}
			if keyval.Ttl.AsDuration() != 0 {
				t.Errorf("expected %q, got %q", snapshotKV[keyval.Key], keyval.Value)
			}
		}
	})

	t.Run("Restore", func(t *testing.T) {
		// Place some keys that we don't want to see return
		// after the snapshot is restored.
		restoreKV := map[string]string{
			"Restore/key1": "value1",
			"Restore/key2": "value2",
		}
		for key, value := range restoreKV {
			if err := meshStorage.PutValue(ctx, key, value, 0); err != nil {
				t.Fatalf("failed to put key: %v", err)
			}
		}
		// Drop all keys from the Snapshot test and then restore the snapshot.
		// We should be able to get the keys back.
		for key := range snapshotKV {
			if err := meshStorage.Delete(ctx, key); err != nil {
				t.Fatalf("failed to delete key: %v", err)
			}
		}
		// Make sure they are indeed gone
		for key := range snapshotKV {
			_, err := meshStorage.GetValue(ctx, key)
			if !IsKeyNotFoundError(err) {
				t.Errorf("expected ErrKeyNotFound, got %v", err)
			}
		}
		// Restore the snapshot
		if err := meshStorage.Restore(ctx, snapshot); err != nil {
			t.Fatalf("failed to restore snapshot: %v", err)
		}
		// Make sure we can get the keys back
		for key, value := range snapshotKV {
			got, err := meshStorage.GetValue(ctx, key)
			if err != nil {
				t.Fatalf("failed to get key: %v", err)
			}
			if got != value {
				t.Errorf("expected %q, got %q", value, got)
			}
		}
		// Make sure the keys we don't want to see are still gone
		for key := range restoreKV {
			_, err := meshStorage.GetValue(ctx, key)
			if !IsKeyNotFoundError(err) {
				t.Errorf("expected ErrKeyNotFound, got %v", err)
			}
		}
	})
}

// RunDualStorageConformance tests that the DualStorage interface is implemented correctly.
func RunDualStorageConformance(t *testing.T, dualStorage DualStorage) {
	t.Helper()
	RunRaftStorageConformance(t, dualStorage)
	RunMeshStorageConformance(t, dualStorage)
}
