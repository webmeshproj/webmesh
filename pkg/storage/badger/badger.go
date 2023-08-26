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

// Package badger implements a storage backend using badger.
package badger

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/pb"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/proto"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

type badgerStorage struct {
	db *badger.DB
	mu sync.RWMutex
}

func New(opts *storage.Options) (storage.Storage, error) {
	var badgeropts badger.Options
	if opts.InMemory {
		badgeropts = badger.DefaultOptions("").WithInMemory(true)
	} else {
		badgeropts = badger.DefaultOptions(opts.DiskPath)
	}
	if !opts.Silent {
		badgeropts.Logger = &logger{slog.Default().With("component", "badger")}
	} else {
		badgeropts.Logger = &logger{slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))}
	}
	db, err := badger.Open(badgeropts)
	if err != nil {
		return nil, fmt.Errorf("badger open: %w", err)
	}
	return &badgerStorage{db: db}, nil
}

// Get returns the value of a key.
func (b *badgerStorage) Get(ctx context.Context, key string) (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if key == "" {
		return "", errors.New("badger get: key is empty")
	}
	var value string
	err := b.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return storage.ErrKeyNotFound
			}
			return fmt.Errorf("badger get: %w", err)
		}
		err = item.Value(func(val []byte) error {
			value = string(val)
			return nil
		})
		if err != nil {
			return fmt.Errorf("badger get: %w", err)
		}
		return nil
	})
	if err != nil && err == badger.ErrKeyNotFound {
		return "", storage.ErrKeyNotFound
	}
	return value, err
}

// Put sets the value of a key.
func (b *badgerStorage) Put(ctx context.Context, key, value string, ttl time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if key == "" {
		return errors.New("badger put: key is empty")
	}
	err := b.db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry([]byte(key), []byte(value))
		if ttl > 0 {
			e = e.WithTTL(ttl)
		}
		err := txn.SetEntry(e)
		if err != nil {
			return fmt.Errorf("badger put: %w", err)
		}
		return nil
	})
	return err
}

// Delete removes a key.
func (b *badgerStorage) Delete(ctx context.Context, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if key == "" {
		return errors.New("badger delete: key is empty")
	}
	err := b.db.Update(func(txn *badger.Txn) error {
		err := txn.Delete([]byte(key))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				return storage.ErrKeyNotFound
			}
			return fmt.Errorf("badger delete: %w", err)
		}
		return nil
	})
	return err
}

// List returns all keys with a given prefix.
func (b *badgerStorage) List(ctx context.Context, prefix string) ([]string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var keys []string
	err := b.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek([]byte(prefix)); it.ValidForPrefix([]byte(prefix)); it.Next() {
			item := it.Item()
			k := item.Key()
			keys = append(keys, string(k))
		}
		return nil
	})
	return keys, err
}

// IterPrefix iterates over all keys with a given prefix.
func (b *badgerStorage) IterPrefix(ctx context.Context, prefix string, fn storage.PrefixIterator) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	err := b.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek([]byte(prefix)); it.ValidForPrefix([]byte(prefix)); it.Next() {
			item := it.Item()
			k := item.Key()
			err := item.Value(func(v []byte) error {
				return fn(string(k), string(v))
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

// Snapshot returns a snapshot of the storage.
func (b *badgerStorage) Snapshot(ctx context.Context) (io.Reader, error) {
	// Take an exclusive lock to prevent any writes while we snapshot.
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.db.Opts().InMemory {
		err := b.db.RunValueLogGC(0.5)
		if err != nil && !errors.Is(err, badger.ErrNoRewrite) {
			return nil, fmt.Errorf("badger run log gc: %w", err)
		}
	}
	data := v1.RaftSnapshot{
		Kv: make(map[string]string),
	}
	err := b.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			k := item.Key()
			err := item.Value(func(v []byte) error {
				data.Kv[string(k)] = string(v)
				return nil
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
	kvdata, err := proto.Marshal(&data)
	if err != nil {
		return nil, fmt.Errorf("badger snapshot: %w", err)
	}
	return bytes.NewReader(kvdata), nil
}

// Restore restores a snapshot of the storage.
func (b *badgerStorage) Restore(ctx context.Context, r io.Reader) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	err := b.db.DropAll()
	if err != nil {
		return fmt.Errorf("badger restore: %w", err)
	}
	data := v1.RaftSnapshot{}
	kvdata, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("badger restore: %w", err)
	}
	err = proto.Unmarshal(kvdata, &data)
	if err != nil {
		return fmt.Errorf("badger restore: %w", err)
	}
	err = b.db.Update(func(txn *badger.Txn) error {
		for k, v := range data.Kv {
			err := txn.Set([]byte(k), []byte(v))
			if err != nil {
				return fmt.Errorf("badger restore: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("badger restore: %w", err)
	}
	return nil
}

// Subscribe will call the given function whenever a key with the given prefix is changed.
// The returned function can be called to unsubscribe. If the given context is cancelled,
// the subscription will be automatically unsubscribed.
func (b *badgerStorage) Subscribe(ctx context.Context, prefix string, fn storage.SubscribeFunc) (func(), error) {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		sub := func(kv *badger.KVList) error {
			for _, keyval := range kv.GetKv() {
				fn(string(keyval.Key), string(keyval.Value))
			}
			return nil
		}
		err := b.db.Subscribe(ctx, sub, []pb.Match{{Prefix: []byte(prefix)}})
		if err != nil && err != context.Canceled {
			context.LoggerFrom(ctx).Error(fmt.Sprintf("badger subscribe: %v", err))
		}
	}()
	return cancel, nil
}

// Close closes the storage.
func (b *badgerStorage) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.db.Close()
}

// logger wraps the default slog.Logger to satisfy the badger.Logger interface.
type logger struct {
	*slog.Logger
}

func (l *logger) Errorf(msg string, args ...any) {
	l.Logger.Error(format(msg, args))
}
func (l *logger) Warningf(msg string, args ...any) {
	l.Logger.Warn(format(msg, args))
}

func (l *logger) Infof(msg string, args ...any) {
	l.Logger.Info(format(msg, args))
}

func (l *logger) Debugf(msg string, args ...any) {
	l.Logger.Debug(format(msg, args))
}

func format(msg string, args []any) string {
	return strings.TrimSpace(fmt.Sprintf(msg, args...))
}
