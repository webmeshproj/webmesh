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
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"
	"github.com/nutsdb/nutsdb"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/webmeshproj/webmesh/pkg/storage"
)

type nutsDiskStorage struct {
	firstIndex, lastIndex atomic.Uint64
	store                 *nutsdb.DB
	subs                  *subscriptionManager
	meshmu                sync.RWMutex
	raftmu                sync.RWMutex
}

// New returns a new RoseDB storage. The returned storage can be used
// for both the mesh and Raft.
func newDiskStorage(storagePath string) (storage.DualStorage, error) {
	db, err := nutsdb.Open(
		nutsdb.DefaultOptions,
		nutsdb.WithDir(storagePath),
	)
	if err != nil {
		return nil, fmt.Errorf("open nutsdb: %w", err)
	}
	// Get first, last index from db and set them
	var first, last uint64
	err = db.View(func(tx *nutsdb.Tx) error {
		entries, err := tx.PrefixScan(logStoreBucket, []byte(""), 0, math.MaxInt)
		if err != nil {
			if !errors.Is(err, nutsdb.ErrPrefixScan) {
				return fmt.Errorf("get first, last raft index: %w", err)
			}
			return nil
		}
		for _, entry := range entries {
			index := binary.BigEndian.Uint64(entry.Key)
			if index < first {
				first = index
			}
			if index > last {
				last = index
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	st := &nutsDiskStorage{
		store: db,
		subs:  newSubscriptionManager(),
	}
	st.firstIndex.Store(first)
	st.lastIndex.Store(last)
	return st, nil
}

// Mesh Storage Operations

// GetValue returns the value of a key.
func (db *nutsDiskStorage) GetValue(ctx context.Context, key string) (string, error) {
	db.meshmu.RLock()
	defer db.meshmu.RUnlock()
	var value string
	err := db.store.View(func(tx *nutsdb.Tx) error {
		entry, err := tx.Get(meshStoreBucket, []byte(key))
		if err != nil {
			return fmt.Errorf("get value: %w", err)
		}
		value = string(entry.Value)
		return nil
	})
	if err != nil {
		if isNotFoundErr(err) {
			return "", storage.NewKeyNotFoundError(key)
		}
		return "", err
	}
	return value, nil
}

// PutValue sets the value of a key. TTL is optional and can be set to 0.
func (db *nutsDiskStorage) PutValue(ctx context.Context, key, value string, ttl time.Duration) error {
	db.meshmu.Lock()
	err := db.store.Update(func(tx *nutsdb.Tx) error {
		err := tx.Put(meshStoreBucket, []byte(key), []byte(value), uint32(ttl.Seconds()))
		if err != nil {
			return fmt.Errorf("put value: %w", err)
		}
		return nil
	})
	db.meshmu.Unlock()
	if err != nil {
		return err
	}
	db.subs.Notify(key, value)
	return nil
}

// Delete removes a key.
func (db *nutsDiskStorage) Delete(ctx context.Context, key string) error {
	db.meshmu.Lock()
	err := db.store.Update(func(tx *nutsdb.Tx) error {
		err := tx.Delete(meshStoreBucket, []byte(key))
		if err != nil {
			return fmt.Errorf("delete value: %w", err)
		}
		return nil
	})
	db.meshmu.Unlock()
	if err == nil {
		db.subs.Notify(key, "")
	}
	return ignoreNotFound(err)
}

// List returns all keys with a given prefix.
func (db *nutsDiskStorage) List(ctx context.Context, prefix string) ([]string, error) {
	db.meshmu.RLock()
	defer db.meshmu.RUnlock()
	var keys []string
	err := db.store.View(func(tx *nutsdb.Tx) error {
		entries, err := tx.PrefixScan(meshStoreBucket, []byte(prefix), 0, math.MaxInt)
		if err != nil {
			return fmt.Errorf("list values: %w", err)
		}
		for _, entry := range entries {
			keys = append(keys, string(entry.Key))
		}
		return nil
	})
	return keys, ignoreNotFound(err)
}

// IterPrefix iterates over all keys with a given prefix. It is important
// that the iterator not attempt any write operations as this will cause
// a deadlock.
func (db *nutsDiskStorage) IterPrefix(ctx context.Context, prefix string, fn storage.PrefixIterator) error {
	db.meshmu.RLock()
	defer db.meshmu.RUnlock()
	err := db.store.View(func(tx *nutsdb.Tx) error {
		entries, err := tx.PrefixScan(meshStoreBucket, []byte(prefix), 0, math.MaxInt)
		if err != nil {
			return fmt.Errorf("iter prefix: %w", err)
		}
		for _, entry := range entries {
			err = fn(string(entry.Key), string(entry.Value))
			if err != nil {
				return err
			}
		}
		return nil
	})
	return ignoreNotFound(err)
}

// Snapshot returns a snapshot of the storage.
func (db *nutsDiskStorage) Snapshot(ctx context.Context) (io.Reader, error) {
	db.meshmu.Lock()
	defer db.meshmu.Unlock()
	snapshot := &v1.RaftSnapshot{
		Kv: make(map[string]*v1.RaftDataItem),
	}
	err := db.store.View(func(tx *nutsdb.Tx) error {
		entries, err := tx.PrefixScan(meshStoreBucket, []byte(""), 0, math.MaxInt)
		if err != nil {
			return fmt.Errorf("snapshot: %w", err)
		}
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
		return nil
	})
	if err != nil && !isNotFoundErr(err) {
		return nil, err
	}
	data, err := proto.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	return bytes.NewReader(data), nil
}

// Restore restores a snapshot of the storage.
func (db *nutsDiskStorage) Restore(ctx context.Context, r io.Reader) error {
	db.meshmu.Lock()
	defer db.meshmu.Unlock()
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	var snapshot v1.RaftSnapshot
	err = proto.Unmarshal(data, &snapshot)
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	err = db.store.Update(func(tx *nutsdb.Tx) error {
		err := tx.DeleteBucket(0, meshStoreBucket)
		if err != nil {
			return fmt.Errorf("restore: %w", err)
		}
		for _, item := range snapshot.Kv {
			err = tx.Put(meshStoreBucket, []byte(item.Key), []byte(item.Value), uint32(item.Ttl.Seconds))
			if err != nil {
				return fmt.Errorf("restore: %w", err)
			}
		}
		return nil
	})
	return err
}

// Subscribe will call the given function whenever a key with the given prefix is changed.
// The returned function can be called to unsubscribe.
func (db *nutsDiskStorage) Subscribe(ctx context.Context, prefix string, fn storage.SubscribeFunc) (context.CancelFunc, error) {
	return db.subs.Subscribe(ctx, prefix, fn)
}

// Close closes the storage.
func (db *nutsDiskStorage) Close() error {
	db.meshmu.Lock()
	defer db.meshmu.Unlock()
	db.raftmu.Lock()
	defer db.raftmu.Unlock()
	db.subs.Close()
	return db.store.Close()
}

// Raft Log Storage Operations

// FirstIndex returns the first index written. 0 for no entries.
func (db *nutsDiskStorage) FirstIndex() (uint64, error) {
	return db.firstIndex.Load(), nil
}

// LastIndex returns the last index written. 0 for no entries.
func (db *nutsDiskStorage) LastIndex() (uint64, error) {
	return db.lastIndex.Load(), nil
}

// GetLog gets a log entry at a given index.
func (db *nutsDiskStorage) GetLog(index uint64, log *raft.Log) error {
	db.raftmu.RLock()
	defer db.raftmu.RUnlock()
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], index)
	err := db.store.View(func(tx *nutsdb.Tx) error {
		entry, err := tx.Get(logStoreBucket, key[:])
		if err != nil {
			return fmt.Errorf("get log: %w", err)
		}
		err = gob.NewDecoder(bytes.NewReader(entry.Value)).Decode(log)
		if err != nil {
			return fmt.Errorf("get log: %w", err)
		}
		return nil
	})
	if err != nil {
		if isNotFoundErr(err) {
			return raft.ErrLogNotFound
		}
		return err
	}
	return nil
}

// StoreLog stores a log entry.
func (db *nutsDiskStorage) StoreLog(log *raft.Log) error {
	db.raftmu.Lock()
	defer db.raftmu.Unlock()
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(log)
	if err != nil {
		return fmt.Errorf("store log: %w", err)
	}
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], log.Index)
	err = db.store.Update(func(tx *nutsdb.Tx) error {
		err = tx.Put(logStoreBucket, key[:], buf.Bytes(), 0)
		if err != nil {
			return fmt.Errorf("store log: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if log.Index < db.lastIndex.Load() {
		db.lastIndex.Store(log.Index)
	}
	return nil
}

// StoreLogs stores multiple log entries. By default the logs stored may not be contiguous with previous logs (i.e. may have a gap in Index since the last log written). If an implementation can't tolerate this it may optionally implement `MonotonicLogStore` to indicate that this is not allowed. This changes Raft's behaviour after restoring a user snapshot to remove all previous logs instead of relying on a "gap" to signal the discontinuity between logs before the snapshot and logs after.
func (db *nutsDiskStorage) StoreLogs(logs []*raft.Log) error {
	db.raftmu.Lock()
	defer db.raftmu.Unlock()
	err := db.store.Update(func(tx *nutsdb.Tx) error {
		for _, log := range logs {
			var buf bytes.Buffer
			err := gob.NewEncoder(&buf).Encode(log)
			if err != nil {
				return fmt.Errorf("store logs: %w", err)
			}
			var key [8]byte
			binary.BigEndian.PutUint64(key[:], log.Index)
			err = tx.Put(logStoreBucket, key[:], buf.Bytes(), 0)
			if err != nil {
				return fmt.Errorf("store logs: %w", err)
			}
		}
		return nil
	})
	return err
}

// DeleteRange deletes a range of log entries. The range is inclusive.
func (db *nutsDiskStorage) DeleteRange(min, max uint64) error {
	db.raftmu.Lock()
	defer db.raftmu.Unlock()
	err := db.store.Update(func(tx *nutsdb.Tx) error {
		entries, err := tx.PrefixScan(logStoreBucket, []byte(""), 0, math.MaxInt)
		if err != nil {
			if isNotFoundErr(err) {
				return nil
			}
			return fmt.Errorf("delete range: %w", err)
		}
		for _, entry := range entries {
			index := binary.BigEndian.Uint64(entry.Key)
			if index >= min && index <= max {
				err = tx.Delete(logStoreBucket, entry.Key)
				if err != nil {
					return fmt.Errorf("delete range: %w", err)
				}
			}
		}
		return nil
	})
	if err != nil {
		if isNotFoundErr(err) {
			return nil
		}
	}
	return err
}

// Raft Stable Storage Operations

func (db *nutsDiskStorage) Set(key []byte, val []byte) error {
	db.raftmu.Lock()
	defer db.raftmu.Unlock()
	err := db.store.Update(func(tx *nutsdb.Tx) error {
		err := tx.Put(stableStoreBucket, key, val, 0)
		if err != nil {
			return fmt.Errorf("set stable store: %w", err)
		}
		return nil
	})
	return err
}

// Get returns the value for key, or an empty byte slice if key was not found.
func (db *nutsDiskStorage) Get(key []byte) ([]byte, error) {
	db.raftmu.RLock()
	defer db.raftmu.RUnlock()
	var val []byte
	err := db.store.View(func(tx *nutsdb.Tx) error {
		entry, err := tx.Get(stableStoreBucket, key)
		if err != nil {
			return fmt.Errorf("get stable store: %w", err)
		}
		val = entry.Value
		return nil
	})
	return val, ignoreNotFound(err)
}

func (db *nutsDiskStorage) SetUint64(key []byte, val uint64) error {
	db.raftmu.Lock()
	defer db.raftmu.Unlock()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], val)
	err := db.store.Update(func(tx *nutsdb.Tx) error {
		err := tx.Put(stableStoreBucket, key, buf[:], 0)
		if err != nil {
			return fmt.Errorf("set stable store: %w", err)
		}
		return nil
	})
	return err
}

// GetUint64 returns the uint64 value for key, or 0 if key was not found.
func (db *nutsDiskStorage) GetUint64(key []byte) (uint64, error) {
	db.raftmu.RLock()
	defer db.raftmu.RUnlock()
	var val [8]byte
	err := db.store.View(func(tx *nutsdb.Tx) error {
		entry, err := tx.Get(stableStoreBucket, key)
		if err != nil {
			return fmt.Errorf("get stable store: %w", err)
		}
		copy(val[:], entry.Value)
		return nil
	})
	return binary.BigEndian.Uint64(val[:]), ignoreNotFound(err)
}
