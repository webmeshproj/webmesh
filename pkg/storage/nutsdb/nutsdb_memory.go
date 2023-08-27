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

// Package nutsdb implements the storage backends using NutsDB.
package nutsdb

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"
	"github.com/nutsdb/nutsdb/inmemory"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/webmeshproj/webmesh/pkg/storage"
)

type nutsInmemStorage struct {
	firstIndex, lastIndex atomic.Uint64
	memstore              *inmemory.DB
	subs                  *subscriptionManager
	meshmu                sync.RWMutex
	raftmu                sync.RWMutex
}

// New returns a new RoseDB storage. The returned storage can be used
// for both the mesh and Raft.
func newInMemoryStorage() (storage.DualStorage, error) {
	db, err := inmemory.Open(inmemory.DefaultOptions)
	if err != nil {
		return nil, fmt.Errorf("open in-memory storage: %w", err)
	}
	// Get first, last index from db and set them
	var first, last uint64
	entries, _, err := db.PrefixScan(logStoreBucket, []byte(""), 0, math.MaxInt)
	if err != nil {
		if !isNotFoundErr(err) {
			return nil, fmt.Errorf("get first, last raft index: %w", err)
		}
	} else {
		for _, entry := range entries {
			index := binary.BigEndian.Uint64(entry.Key)
			if index < first {
				first = index
			}
			if index > last {
				last = index
			}
		}
	}
	st := &nutsInmemStorage{
		memstore: db,
		subs:     newSubscriptionManager(),
	}
	st.firstIndex.Store(first)
	st.lastIndex.Store(last)
	return st, nil
}

// Mesh Storage Operations

// GetValue returns the value of a key.
func (db *nutsInmemStorage) GetValue(ctx context.Context, key string) (string, error) {
	db.meshmu.RLock()
	defer db.meshmu.RUnlock()
	value, err := db.memstore.Get(meshStoreBucket, []byte(key))
	if err != nil {
		if isNotFoundErr(err) {
			return "", storage.NewKeyNotFoundError(key)
		}
		return "", fmt.Errorf("get value: %w", err)
	}
	return string(value.Value), nil
}

// PutValue sets the value of a key. TTL is optional and can be set to 0.
func (db *nutsInmemStorage) PutValue(ctx context.Context, key, value string, ttl time.Duration) error {
	db.meshmu.Lock()
	err := db.memstore.Put(meshStoreBucket, []byte(key), []byte(value), uint32(ttl.Seconds()))
	db.meshmu.Unlock()
	if err != nil {
		return fmt.Errorf("put value: %w", err)
	}
	db.subs.Notify(key, value)
	return nil
}

// Delete removes a key.
func (db *nutsInmemStorage) Delete(ctx context.Context, key string) error {
	db.meshmu.Lock()
	err := db.memstore.Delete(meshStoreBucket, []byte(key))
	db.meshmu.Unlock()
	if err == nil {
		db.subs.Notify(key, "")
	}
	return ignoreNotFound(err)
}

// List returns all keys with a given prefix.
func (db *nutsInmemStorage) List(ctx context.Context, prefix string) ([]string, error) {
	db.meshmu.RLock()
	defer db.meshmu.RUnlock()
	entries, _, err := db.memstore.PrefixScan(meshStoreBucket, []byte(prefix), 0, math.MaxInt)
	if err != nil {
		if isNotFoundErr(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list: %w", err)
	}
	var keys []string
	for _, entry := range entries {
		keys = append(keys, string(entry.Key))
	}
	return keys, nil
}

// IterPrefix iterates over all keys with a given prefix. It is important
// that the iterator not attempt any write operations as this will cause
// a deadlock.
func (db *nutsInmemStorage) IterPrefix(ctx context.Context, prefix string, fn storage.PrefixIterator) error {
	db.meshmu.RLock()
	defer db.meshmu.RUnlock()
	entries, _, err := db.memstore.PrefixScan(meshStoreBucket, []byte(prefix), 0, math.MaxInt)
	if err != nil {
		if isNotFoundErr(err) {
			return nil
		}
		return fmt.Errorf("iter prefix: %w", err)
	}
	for _, entry := range entries {
		err = fn(string(entry.Key), string(entry.Value))
		if err != nil {
			return fmt.Errorf("iter prefix: %w", err)
		}
	}
	return nil
}

// Snapshot returns a snapshot of the storage.
func (db *nutsInmemStorage) Snapshot(ctx context.Context) (io.Reader, error) {
	db.meshmu.Lock()
	defer db.meshmu.Unlock()
	snapshot := &v1.RaftSnapshot{
		Kv: make(map[string]*v1.RaftDataItem),
	}
	entries, _, err := db.memstore.PrefixScan(meshStoreBucket, []byte(""), 0, math.MaxInt)
	if err != nil {
		if !isNotFoundErr(err) {
			return nil, fmt.Errorf("snapshot: %w", err)
		}
	} else {
		for _, entry := range entries {
			var ttl time.Duration
			if entry.Meta != nil {
				ttl = time.Duration(entry.Meta.TTL) * time.Second
			}
			snapshot.Kv[string(entry.Key)] = &v1.RaftDataItem{
				Key:   string(entry.Key),
				Value: string(entry.Value),
				Ttl:   durationpb.New(ttl),
			}
		}
	}
	data, err := proto.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	return bytes.NewReader(data), nil
}

// Restore restores a snapshot of the storage.
func (db *nutsInmemStorage) Restore(ctx context.Context, r io.Reader) error {
	db.meshmu.Lock()
	defer db.meshmu.Unlock()
	// First delete the storage to clear it out.
	entries, _, err := db.memstore.PrefixScan(meshStoreBucket, []byte(""), 0, math.MaxInt)
	if err != nil {
		if !isNotFoundErr(err) {
			return fmt.Errorf("restore: %w", err)
		}
	} else {
		for _, entry := range entries {
			err = db.memstore.Delete(meshStoreBucket, entry.Key)
			if err != nil {
				return fmt.Errorf("restore: %w", err)
			}
		}
	}
	// Now restore the snapshot.
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	var snapshot v1.RaftSnapshot
	err = proto.Unmarshal(data, &snapshot)
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	for _, item := range snapshot.Kv {
		err = db.memstore.Put(meshStoreBucket, []byte(item.Key), []byte(item.Value), uint32(item.Ttl.AsDuration().Seconds()))
		if err != nil {
			return fmt.Errorf("restore: %w", err)
		}
	}
	return nil
}

// Subscribe will call the given function whenever a key with the given prefix is changed.
// The returned function can be called to unsubscribe.
func (db *nutsInmemStorage) Subscribe(ctx context.Context, prefix string, fn storage.SubscribeFunc) (context.CancelFunc, error) {
	return db.subs.Subscribe(ctx, prefix, fn)
}

// Close closes the storage.
func (db *nutsInmemStorage) Close() error {
	db.meshmu.Lock()
	defer db.meshmu.Unlock()
	db.raftmu.Lock()
	defer db.raftmu.Unlock()
	db.subs.Close()
	return nil
}

// Raft Log Storage Operations

// FirstIndex returns the first index written. 0 for no entries.
func (db *nutsInmemStorage) FirstIndex() (uint64, error) {
	return db.firstIndex.Load(), nil
}

// LastIndex returns the last index written. 0 for no entries.
func (db *nutsInmemStorage) LastIndex() (uint64, error) {
	return db.lastIndex.Load(), nil
}

// GetLog gets a log entry at a given index.
func (db *nutsInmemStorage) GetLog(index uint64, log *raft.Log) error {
	db.raftmu.RLock()
	defer db.raftmu.RUnlock()
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], index)
	entry, err := db.memstore.Get(logStoreBucket, key[:])
	if err != nil {
		if isNotFoundErr(err) {
			return raft.ErrLogNotFound
		}
		return fmt.Errorf("get log: %w", err)
	}
	err = gob.NewDecoder(bytes.NewReader(entry.Value)).Decode(log)
	if err != nil {
		return fmt.Errorf("get log: %w", err)
	}
	return nil
}

// StoreLog stores a log entry.
func (db *nutsInmemStorage) StoreLog(log *raft.Log) error {
	db.raftmu.Lock()
	defer db.raftmu.Unlock()
	return db.storeLog(log)
}

// StoreLogs stores multiple log entries. By default the logs stored may not be contiguous with previous logs (i.e. may have a gap in Index since the last log written). If an implementation can't tolerate this it may optionally implement `MonotonicLogStore` to indicate that this is not allowed. This changes Raft's behaviour after restoring a user snapshot to remove all previous logs instead of relying on a "gap" to signal the discontinuity between logs before the snapshot and logs after.
func (db *nutsInmemStorage) StoreLogs(logs []*raft.Log) error {
	db.raftmu.Lock()
	defer db.raftmu.Unlock()
	for _, log := range logs {
		err := db.storeLog(log)
		if err != nil {
			return fmt.Errorf("store logs: %w", err)
		}
	}
	return nil
}

func (db *nutsInmemStorage) storeLog(log *raft.Log) error {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(log)
	if err != nil {
		return fmt.Errorf("store log: %w", err)
	}
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], log.Index)
	err = db.memstore.Put(logStoreBucket, key[:], buf.Bytes(), 0)
	if err != nil {
		return fmt.Errorf("store log: %w", err)
	}
	if log.Index < db.lastIndex.Load() {
		db.lastIndex.Store(log.Index)
	}
	return nil
}

// DeleteRange deletes a range of log entries. The range is inclusive.
func (db *nutsInmemStorage) DeleteRange(min, max uint64) error {
	db.raftmu.Lock()
	defer db.raftmu.Unlock()
	entries, _, err := db.memstore.PrefixScan(logStoreBucket, []byte(""), 0, math.MaxInt)
	if err != nil {
		if isNotFoundErr(err) {
			return nil
		}
		return fmt.Errorf("delete range: %w", err)
	}
	for _, entry := range entries {
		index := binary.BigEndian.Uint64(entry.Key)
		if index >= min && index <= max {
			err = db.memstore.Delete(logStoreBucket, entry.Key)
			if err != nil {
				return fmt.Errorf("delete range: %w", err)
			}
		}
	}
	return nil
}

// Raft Stable Storage Operations

func (db *nutsInmemStorage) Set(key []byte, val []byte) error {
	db.raftmu.Lock()
	defer db.raftmu.Unlock()
	err := db.memstore.Put(stableStoreBucket, key, val, 0)
	if err != nil {
		return fmt.Errorf("set stable store: %w", err)
	}
	return nil
}

// Get returns the value for key, or an empty byte slice if key was not found.
func (db *nutsInmemStorage) Get(key []byte) ([]byte, error) {
	db.raftmu.RLock()
	defer db.raftmu.RUnlock()
	val, err := db.memstore.Get(stableStoreBucket, key)
	if err != nil {
		if isNotFoundErr(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get stable store: %w", err)
	}
	return val.Value, nil
}

func (db *nutsInmemStorage) SetUint64(key []byte, val uint64) error {
	db.raftmu.Lock()
	defer db.raftmu.Unlock()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], val)
	err := db.memstore.Put(stableStoreBucket, key, buf[:], 0)
	if err != nil {
		return fmt.Errorf("set stable store: %w", err)
	}
	return nil
}

// GetUint64 returns the uint64 value for key, or 0 if key was not found.
func (db *nutsInmemStorage) GetUint64(key []byte) (uint64, error) {
	db.raftmu.RLock()
	defer db.raftmu.RUnlock()
	val, err := db.memstore.Get(stableStoreBucket, key)
	if err != nil {
		if isNotFoundErr(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("get stable store: %w", err)
	}
	return binary.BigEndian.Uint64(val.Value), nil
}
