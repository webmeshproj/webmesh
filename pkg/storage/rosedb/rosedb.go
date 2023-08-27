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

// Package rosedb implements the storage backends using RoseDB.
package rosedb

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"math"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flower-corp/rosedb"
	"github.com/hashicorp/raft"

	"github.com/webmeshproj/webmesh/pkg/storage"
)

type Storage interface {
	storage.MeshStorage
	storage.RaftStorage
}

type roseDBStorage struct {
	firstIndex, lastIndex atomic.Uint64
	store                 *rosedb.RoseDB
	meshmu                sync.RWMutex
	raftmu                sync.RWMutex
}

// New returns a new RoseDB storage. The returned storage can be used
// for both the mesh and Raft.
func New(storagePath string) (Storage, error) {
	opts := rosedb.DefaultOptions(storagePath)
	opts.IoType = rosedb.MMap
	db, err := rosedb.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open RoseDB: %w", err)
	}
	// Check if any raft logs exist.
	var firstIndex, lastIndex uint64
	data, err := db.Scan([]byte(logStorePrefix), "[0-9]+", math.MaxInt)
	if err != nil {
		return nil, fmt.Errorf("scan raft logs: %w", err)
	}
	for i := 0; i < len(data); i += 2 {
		key := data[i]
		numBytes := bytes.TrimPrefix(key, []byte(logStorePrefix))
		index, err := strconv.ParseUint(string(numBytes), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse raft log index: %w", err)
		}
		if index > lastIndex {
			lastIndex = index
		}
		if firstIndex == 0 || index < firstIndex {
			firstIndex = index
		}
	}
	st := &roseDBStorage{
		store: db,
	}
	st.firstIndex.Store(firstIndex)
	st.lastIndex.Store(lastIndex)
	return st, nil
}

// Mesh Storage Operations

// GetValue returns the value of a key.
func (db *roseDBStorage) GetValue(ctx context.Context, key string) (string, error) {
	db.meshmu.RLock()
	defer db.meshmu.RUnlock()
	return "", nil
}

// PutValue sets the value of a key. TTL is optional and can be set to 0.
func (db *roseDBStorage) PutValue(ctx context.Context, key, value string, ttl time.Duration) error {
	db.meshmu.Lock()
	defer db.meshmu.Unlock()
	return nil
}

// Delete removes a key.
func (db *roseDBStorage) Delete(ctx context.Context, key string) error {
	db.meshmu.Lock()
	defer db.meshmu.Unlock()
	return nil
}

// List returns all keys with a given prefix.
func (db *roseDBStorage) List(ctx context.Context, prefix string) ([]string, error) {
	db.meshmu.RLock()
	defer db.meshmu.RUnlock()
	return nil, nil
}

// IterPrefix iterates over all keys with a given prefix. It is important
// that the iterator not attempt any write operations as this will cause
// a deadlock.
func (db *roseDBStorage) IterPrefix(ctx context.Context, prefix string, fn storage.PrefixIterator) error {
	db.meshmu.RLock()
	defer db.meshmu.RUnlock()
	return nil
}

// Snapshot returns a snapshot of the storage.
func (db *roseDBStorage) Snapshot(ctx context.Context) (io.Reader, error) {
	db.meshmu.Lock()
	defer db.meshmu.Unlock()
	return nil, nil
}

// Restore restores a snapshot of the storage.
func (db *roseDBStorage) Restore(ctx context.Context, r io.Reader) error {
	db.meshmu.Lock()
	defer db.meshmu.Unlock()
	return nil
}

// Subscribe will call the given function whenever a key with the given prefix is changed.
// The returned function can be called to unsubscribe.
func (db *roseDBStorage) Subscribe(ctx context.Context, prefix string, fn storage.SubscribeFunc) (context.CancelFunc, error) {
	return nil, nil
}

// Close closes the storage.
func (db *roseDBStorage) Close() error {
	return nil
}

// Raft Log Storage Operations

const logStorePrefix = "/raft-log/"

// FirstIndex returns the first index written. 0 for no entries.
func (db *roseDBStorage) FirstIndex() (uint64, error) {
	return db.firstIndex.Load(), nil
}

// LastIndex returns the last index written. 0 for no entries.
func (db *roseDBStorage) LastIndex() (uint64, error) {
	return db.lastIndex.Load(), nil
}

// GetLog gets a log entry at a given index.
func (db *roseDBStorage) GetLog(index uint64, log *raft.Log) error {
	db.raftmu.RLock()
	defer db.raftmu.RUnlock()
	key := fmt.Sprintf("%s%d", logStorePrefix, index)
	val, err := db.store.Get([]byte(key))
	if err != nil {
		if err == rosedb.ErrKeyNotFound {
			return raft.ErrLogNotFound
		}
		return fmt.Errorf("get log: %w", err)
	}
	err = gob.NewDecoder(bytes.NewReader(val)).Decode(log)
	if err != nil {
		return fmt.Errorf("decode log: %w", err)
	}
	return nil
}

// StoreLog stores a log entry.
func (db *roseDBStorage) StoreLog(log *raft.Log) error {
	db.raftmu.Lock()
	defer db.raftmu.Unlock()
	return db.storeLog(log)
}

// StoreLogs stores multiple log entries. By default the logs stored may not be contiguous with previous logs (i.e. may have a gap in Index since the last log written). If an implementation can't tolerate this it may optionally implement `MonotonicLogStore` to indicate that this is not allowed. This changes Raft's behaviour after restoring a user snapshot to remove all previous logs instead of relying on a "gap" to signal the discontinuity between logs before the snapshot and logs after.
func (db *roseDBStorage) StoreLogs(logs []*raft.Log) error {
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

func (db *roseDBStorage) storeLog(log *raft.Log) error {
	key := fmt.Sprintf("%s%d", logStorePrefix, log.Index)
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(log)
	if err != nil {
		return fmt.Errorf("encode log: %w", err)
	}
	err = db.store.Set([]byte(key), buf.Bytes())
	if err != nil {
		return fmt.Errorf("store log: %w", err)
	}
	if log.Index > db.lastIndex.Load() {
		db.lastIndex.Store(log.Index)
	}
	return nil
}

// DeleteRange deletes a range of log entries. The range is inclusive.
func (db *roseDBStorage) DeleteRange(min, max uint64) error {
	db.raftmu.Lock()
	defer db.raftmu.Unlock()
	for i := min; i <= max; i++ {
		key := fmt.Sprintf("%s%d", logStorePrefix, i)
		err := db.store.Delete([]byte(key))
		if err != nil {
			return fmt.Errorf("delete range: %w", err)
		}
	}
	return nil
}

// Raft Stable Storage Operations

const stableStorePrefix = "/raft-stable/"

func (db *roseDBStorage) Set(key []byte, val []byte) error {
	db.raftmu.Lock()
	defer db.raftmu.Unlock()
	key = append([]byte(stableStorePrefix), key...)
	err := db.store.Set(key, val)
	if err != nil {
		return fmt.Errorf("set stable-store key %s: %w", string(key), err)
	}
	return nil
}

// Get returns the value for key, or an empty byte slice if key was not found.
func (db *roseDBStorage) Get(key []byte) ([]byte, error) {
	db.raftmu.RLock()
	defer db.raftmu.RUnlock()
	key = append([]byte(stableStorePrefix), key...)
	val, err := db.store.Get(key)
	if err != nil {
		if err == rosedb.ErrKeyNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("get stable-store key %s: %w", string(key), err)
	}
	return val, nil
}

func (db *roseDBStorage) SetUint64(key []byte, val uint64) error {
	db.raftmu.Lock()
	defer db.raftmu.Unlock()
	key = append([]byte(stableStorePrefix), key...)
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, val)
	err := db.store.Set(key, data)
	if err != nil {
		return fmt.Errorf("set stable-store key %s: %w", string(key), err)
	}
	return nil
}

// GetUint64 returns the uint64 value for key, or 0 if key was not found.
func (db *roseDBStorage) GetUint64(key []byte) (uint64, error) {
	db.raftmu.RLock()
	defer db.raftmu.RUnlock()
	key = append([]byte(stableStorePrefix), key...)
	val, err := db.store.Get(key)
	if err != nil {
		if err == rosedb.ErrKeyNotFound {
			return 0, nil
		}
	}
	return binary.BigEndian.Uint64(val), nil
}
