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

// Package badgerdb implements the storage backends using BadgerDB.
package badgerdb

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/pb"
	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// BadgerGoRoutines is the number of goroutines to use for BadgerDB.
var BadgerGoRoutines = 32

func init() {
	if val, ok := os.LookupEnv("WEBMESH_BADGER_GOROUTINES"); ok {
		i, err := strconv.Atoi(val)
		if err == nil {
			BadgerGoRoutines = i
		}
	}
}

// Options are the options for creating a new NutsDB storage.
type Options struct {
	// InMemory specifies whether to use an in-memory storage.
	InMemory bool
	// DiskPath is the path to use for disk storage.
	DiskPath string
	// SyncWrites specifies whether to sync writes to disk.
	SyncWrites bool
	// Debug specifies whether to enable debug logging.
	Debug bool
}

type badgerDB struct {
	opts              Options
	db                *badger.DB
	firstIdx, lastIdx atomic.Uint64
	mu                sync.Mutex
}

// New creates a new BadgerDB storage.
func New(opts Options) (storage.DualStorage, error) {
	if opts.InMemory {
		return NewInMemory(opts)
	}
	badgeropts := badger.
		DefaultOptions(opts.DiskPath).
		WithNumGoroutines(BadgerGoRoutines)
	if opts.SyncWrites {
		badgeropts = badgeropts.WithSyncWrites(true)
	}
	badgeropts = badgeropts.WithLogger(logging.NewBadgerLogger(""))
	if opts.Debug {
		badgeropts = badgeropts.WithLoggingLevel(badger.DEBUG).WithLogger(logging.NewBadgerLogger("debug"))
	}
	db, err := badger.Open(badgeropts)
	if err != nil {
		return nil, err
	}
	first, last, err := getFirstAndLastIndex(db)
	if err != nil {
		return nil, err
	}
	bdb := &badgerDB{
		opts: opts,
		db:   db,
	}
	bdb.firstIdx.Store(first)
	bdb.lastIdx.Store(last)
	return bdb, nil
}

// NewInMemory creates a new in-memory BadgerDB storage.
func NewInMemory(opts Options) (storage.DualStorage, error) {
	badgeropts := badger.DefaultOptions("").
		WithInMemory(true).
		WithNumGoroutines(BadgerGoRoutines)
	badgeropts = badgeropts.WithLogger(logging.NewBadgerLogger(""))
	if opts.Debug {
		badgeropts = badgeropts.WithLoggingLevel(badger.DEBUG).WithLogger(logging.NewBadgerLogger("debug"))
	}
	db, err := badger.Open(badgeropts)
	if err != nil {
		return nil, err
	}
	return &badgerDB{
		opts: opts,
		db:   db,
	}, nil
}

// NewTestStorage is a helper method for returning a new in-memory storage
// and panicking on error.
func NewTestStorage(debug bool) storage.DualStorage {
	db, err := NewInMemory(Options{
		Debug: debug,
	})
	if err != nil {
		panic(err)
	}
	return db
}

// NewTestDiskStorage is a helper method for returning a new disk storage
// and panicking on error. The storage is created in a temporary directory
// that is cleaned up when the storage is closed.
func NewTestDiskStorage(debug bool) storage.DualStorage {
	tmp, err := os.MkdirTemp("", "")
	if err != nil {
		panic(err)
	}
	db, err := New(Options{
		DiskPath:   tmp,
		Debug:      debug,
		SyncWrites: true,
	})
	if err != nil {
		panic(err)
	}
	return &TempDiskStorage{
		DualStorage: db,
		tmp:         tmp,
	}
}

type TempDiskStorage struct {
	storage.DualStorage
	tmp string
}

func (t *TempDiskStorage) Close() error {
	_ = t.DualStorage.Close()
	return os.RemoveAll(t.tmp)
}

// DropAll deletes all keys.
func (db *badgerDB) DropAll(ctx context.Context) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.db.DropAll()
}

// GetValue returns the value of a key.
func (db *badgerDB) GetValue(ctx context.Context, key []byte) ([]byte, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	var value []byte
	err := db.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		value, err = item.ValueCopy(nil)
		return err
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, errors.ErrKeyNotFound
		}
		return nil, err
	}
	return value, nil
}

// PutValue sets the value of a key. TTL is optional and can be set to 0.
func (db *badgerDB) PutValue(ctx context.Context, key, value []byte, ttl time.Duration) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.db.Update(func(txn *badger.Txn) error {
		entry := badger.NewEntry(key, value)
		if ttl > 0 {
			entry = entry.WithTTL(ttl)
		}
		return txn.SetEntry(entry)
	})
}

// Delete removes a key.
func (db *badgerDB) Delete(ctx context.Context, key []byte) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	err := db.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		}
		return err
	}
	return nil
}

// ListKeys returns all keys with a given prefix.
func (db *badgerDB) ListKeys(ctx context.Context, prefix []byte) ([][]byte, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	var out [][]byte
	err := db.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		prefix := prefix
		opts.Prefix = prefix
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			k := it.Item().Key()
			key := make([]byte, len(k))
			copy(key, k)
			if bytes.HasPrefix(k, []byte(prefix)) {
				out = append(out, key)
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return out, nil
}

// IterPrefix iterates over all keys with a given prefix. It is important
// that the iterator not attempt any write operations as this will cause
// a deadlock. The iteration will stop if the iterator returns an error.
func (db *badgerDB) IterPrefix(ctx context.Context, prefix []byte, fn storage.PrefixIterator) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	err := db.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		prefix := prefix
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			k := item.Key()
			err := item.Value(func(v []byte) error {
				key, val := make([]byte, len(k)), make([]byte, len(v))
				copy(key, k)
				copy(val, v)
				return fn(key, val)
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		return nil
	}
	return err
}

// Subscribe will call the given function whenever a key with the given prefix is changed.
// The returned function can be called to unsubscribe.
func (db *badgerDB) Subscribe(ctx context.Context, prefix []byte, fn storage.KVSubscribeFunc) (context.CancelFunc, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		match := []pb.Match{}
		if len(prefix) > 0 {
			match = append(match, pb.Match{
				Prefix: prefix,
			})
		} else {
			match = append(match, pb.Match{
				Prefix: types.RegistryPrefix,
			})
		}
		var mu sync.Mutex
		_ = db.db.Subscribe(ctx, func(kv *pb.KVList) error {
			mu.Lock()
			defer mu.Unlock()
			for _, kv := range kv.Kv {
				key, value := make([]byte, len(kv.Key)), make([]byte, len(kv.Value))
				copy(key, kv.Key)
				copy(value, kv.Value)
				fn(key, value)
			}
			return nil
		}, match)
	}()
	return cancel, nil
}

// Snapshot returns a snapshot of the storage.
func (db *badgerDB) Snapshot(ctx context.Context) (io.Reader, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	snapshot := &v1.RaftSnapshot{}
	err := db.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = types.RegistryPrefix
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			if item.IsDeletedOrExpired() {
				return nil
			}
			var ttl time.Duration
			if item.ExpiresAt() > 0 {
				ttl = time.Until(time.Unix(int64(item.ExpiresAt()), 0))
			}
			k := item.KeyCopy(nil)
			value, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}
			snapshot.Kv = append(snapshot.Kv, &v1.RaftDataItem{
				Key:   k,
				Value: value,
				Ttl:   durationpb.New(ttl),
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("badger snapshot: %w", err)
	}
	data, err := proto.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("badger snapshot: %w", err)
	}
	return bytes.NewReader(data), nil
}

// Restore restores a snapshot of the storage.
func (db *badgerDB) Restore(ctx context.Context, r io.Reader) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if r == nil {
		return fmt.Errorf("badger restore: reader is nil")
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("badger restore: %w", err)
	}
	snapshot := &v1.RaftSnapshot{}
	err = proto.Unmarshal(data, snapshot)
	if err != nil {
		return fmt.Errorf("badger restore: %w", err)
	}
	err = db.db.DropAll()
	if err != nil {
		return fmt.Errorf("badger restore: %w", err)
	}
	err = db.db.Update(func(txn *badger.Txn) error {
		for _, kv := range snapshot.Kv {
			var ttl time.Duration
			if kv.Ttl != nil {
				ttl = kv.Ttl.AsDuration()
			}
			entry := badger.NewEntry([]byte(kv.Key), []byte(kv.Value))
			if ttl > 0 {
				entry = entry.WithTTL(ttl)
			}
			err := txn.SetEntry(entry)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("badger restore: %w", err)
	}
	return nil
}

// Close closes the storage.
func (db *badgerDB) Close() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.db.Close()
}

// Raft Log Storage Operations

var RaftLogPrefix = types.ConsensusPrefix.For([]byte("/log/"))

// FirstIndex returns the first index written. 0 for no entries.
func (db *badgerDB) FirstIndex() (uint64, error) {
	return db.firstIdx.Load(), nil
}

// LastIndex returns the last index written. 0 for no entries.
func (db *badgerDB) LastIndex() (uint64, error) {
	return db.lastIdx.Load(), nil
}

// GetLog gets a log entry at a given index.
func (db *badgerDB) GetLog(index uint64, log *raft.Log) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	err := db.db.View(func(txn *badger.Txn) error {
		idx := strconv.Itoa(int(index))
		item, err := txn.Get(append([]byte(RaftLogPrefix), []byte(idx)...))
		if err != nil {
			return err
		}
		val, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		return gob.NewDecoder(bytes.NewReader(val)).Decode(log)
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return raft.ErrLogNotFound
		}
		return fmt.Errorf("get log: %w", err)
	}
	return nil
}

// StoreLog stores a log entry.
func (db *badgerDB) StoreLog(log *raft.Log) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	err := db.db.Update(func(txn *badger.Txn) error {
		return db.storeLog(txn, log)
	})
	if err != nil {
		return fmt.Errorf("store log: %w", err)
	}
	return nil
}

// StoreLogs stores multiple log entries. By default the logs stored may not be contiguous with previous logs (i.e. may have a gap in Index since the last log written). If an implementation can't tolerate this it may optionally implement `MonotonicLogStore` to indicate that this is not allowed. This changes Raft's behaviour after restoring a user snapshot to remove all previous logs instead of relying on a "gap" to signal the discontinuity between logs before the snapshot and logs after.
func (db *badgerDB) StoreLogs(logs []*raft.Log) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	err := db.db.Update(func(txn *badger.Txn) error {
		for _, log := range logs {
			err := db.storeLog(txn, log)
			if err != nil {
				return fmt.Errorf("store log: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("store logs: %w", err)
	}
	return nil
}

func (db *badgerDB) storeLog(txn *badger.Txn, log *raft.Log) error {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(log)
	if err != nil {
		return fmt.Errorf("encode log: %w", err)
	}
	idx := strconv.Itoa(int(log.Index))
	err = txn.Set(append([]byte(RaftLogPrefix), []byte(idx)...), buf.Bytes())
	if err != nil {
		return fmt.Errorf("set log: %w", err)
	}
	if db.firstIdx.Load() == 0 {
		db.firstIdx.Store(log.Index)
	}
	if log.Index > db.lastIdx.Load() {
		db.lastIdx.Store(log.Index)
	}
	return nil
}

// DeleteRange deletes a range of log entries. The range is inclusive.
func (db *badgerDB) DeleteRange(min, max uint64) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	err := db.db.Update(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte(RaftLogPrefix)
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			k := item.Key()
			index := bytes.TrimPrefix(k, []byte(RaftLogPrefix))
			idx, err := strconv.ParseUint(string(index), 10, 64)
			if err != nil {
				return err
			}
			if idx >= min && idx <= max {
				err := txn.Delete(k)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("delete range: %w", err)
	}
	return nil
}

// Raft Stable Storage Operations

var StableStorePrefix = types.ConsensusPrefix.For([]byte("/stable/"))

func (db *badgerDB) Set(key []byte, val []byte) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	err := db.db.Update(func(txn *badger.Txn) error {
		return txn.Set(append([]byte(StableStorePrefix), key...), val)
	})
	if err != nil {
		return fmt.Errorf("set stable store: %w", err)
	}
	return nil
}

// Get returns the value for key, or an empty byte slice if key was not found.
func (db *badgerDB) Get(key []byte) ([]byte, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	var value []byte
	err := db.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(append([]byte(StableStorePrefix), key...))
		if err != nil {
			return err
		}
		value, err = item.ValueCopy(nil)
		return err
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("get stable store: %w", err)
	}
	return value, nil
}

func (db *badgerDB) SetUint64(key []byte, val uint64) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	err := db.db.Update(func(txn *badger.Txn) error {
		return txn.Set(append([]byte(StableStorePrefix), key...), []byte(strconv.Itoa(int(val))))
	})
	if err != nil {
		return fmt.Errorf("set stable store: %w", err)
	}
	return nil
}

// GetUint64 returns the uint64 value for key, or 0 if key was not found.
func (db *badgerDB) GetUint64(key []byte) (uint64, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	var value []byte
	err := db.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(append([]byte(StableStorePrefix), key...))
		if err != nil {
			return err
		}
		value, err = item.ValueCopy(nil)
		return err
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return 0, nil
		}
		return 0, fmt.Errorf("get stable store: %w", err)
	}
	return strconv.ParseUint(string(value), 10, 64)
}

func getFirstAndLastIndex(db *badger.DB) (first, last uint64, err error) {
	err = db.View(func(tx *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = []byte(RaftLogPrefix)
		it := tx.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			k := item.Key()
			idx := bytes.TrimPrefix(k, []byte(RaftLogPrefix))
			index, err := strconv.ParseUint(string(idx), 10, 64)
			if err != nil {
				return err
			}
			if index < first {
				first = index
			}
			if index > last {
				last = index
			}
		}
		return nil
	})
	return
}
