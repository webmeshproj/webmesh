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

// Package memory implements an in-memory storage backend suitable for testing.
package memory

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/webmeshproj/webmesh/pkg/storage"
)

// NewMeshStorage returns a memory-based mesh storage that is only suitable for testing.
func New() storage.DualStorage {
	return &meshStorage{
		InmemStore: raft.NewInmemStore(),
		data:       make(map[string]dataItem),
		subs:       make(map[string]subscription),
	}
}

type meshStorage struct {
	*raft.InmemStore
	data map[string]dataItem
	subs map[string]subscription
	mu   sync.RWMutex
}

type dataItem struct {
	value string
	ttl   time.Time
}

type subscription struct {
	prefix string
	fn     storage.SubscribeFunc
	ctx    context.Context
	cancel context.CancelFunc
}

func (st *meshStorage) DropAll(ctx context.Context) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.data = make(map[string]dataItem)
	for _, sub := range st.subs {
		sub.cancel()
	}
	st.subs = make(map[string]subscription)
	return nil
}

// GetValue returns the value of a key.
func (st *meshStorage) GetValue(ctx context.Context, key string) (string, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	if val, ok := st.data[key]; ok {
		if val.ttl != (time.Time{}) && time.Now().After(val.ttl) {
			delete(st.data, key)
			return "", storage.ErrKeyNotFound
		}
		return val.value, nil
	}
	return "", storage.ErrKeyNotFound
}

// PutValue sets the value of a key. TTL is optional and can be set to 0.
func (st *meshStorage) PutValue(ctx context.Context, key, value string, ttl time.Duration) error {
	st.mu.Lock()
	st.data[key] = dataItem{
		value: value,
		ttl: func() time.Time {
			if ttl == 0 {
				return time.Time{}
			}
			return time.Now().Add(ttl)
		}(),
	}
	st.mu.Unlock()
	for id, sub := range st.subs {
		if strings.HasPrefix(key, sub.prefix) {
			if ctx.Err() != nil {
				delete(st.subs, id)
			} else {
				sub.fn(key, value)
			}
		}
	}
	return nil
}

// Delete removes a key.
func (st *meshStorage) Delete(ctx context.Context, key string) error {
	st.mu.Lock()
	delete(st.data, key)
	st.mu.Unlock()
	for id, sub := range st.subs {
		if strings.HasPrefix(key, sub.prefix) {
			if ctx.Err() != nil {
				delete(st.subs, id)
			} else {
				sub.fn(key, "")
			}
		}
	}
	return nil
}

// List returns all keys with a given prefix.
func (st *meshStorage) List(ctx context.Context, prefix string) ([]string, error) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	var keys []string
	for k := range st.data {
		if strings.HasPrefix(k, prefix) {
			key := k
			keys = append(keys, key)
		}
	}
	return keys, nil
}

// IterPrefix iterates over all keys with a given prefix. It is important
// that the iterator not attempt any write operations as this will cause
// a deadlock.
func (st *meshStorage) IterPrefix(ctx context.Context, prefix string, fn storage.PrefixIterator) error {
	st.mu.RLock()
	defer st.mu.RUnlock()
	for k, v := range st.data {
		if strings.HasPrefix(k, prefix) {
			if v.ttl != (time.Time{}) && time.Now().After(v.ttl) {
				delete(st.data, k)
				continue
			}
			key := k
			val := v
			if err := fn(key, val.value); err != nil {
				return err
			}
		}
	}
	return nil
}

// Snapshot returns a snapshot of the storage.
func (st *meshStorage) Snapshot(ctx context.Context) (io.Reader, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	data := v1.RaftSnapshot{
		Kv: make(map[string]*v1.RaftDataItem),
	}
	for k, v := range st.data {
		if v.ttl != (time.Time{}) && time.Now().After(v.ttl) {
			delete(st.data, k)
			continue
		}
		key := k
		val := v
		var ttl time.Duration
		if !val.ttl.IsZero() {
			ttl = time.Until(val.ttl)
		}
		data.Kv[key] = &v1.RaftDataItem{
			Value: val.value,
			Key:   key,
			Ttl:   durationpb.New(ttl),
		}
	}
	kvdata, err := proto.Marshal(&data)
	if err != nil {
		return nil, fmt.Errorf("memory snapshot: %w", err)
	}
	return bytes.NewReader(kvdata), nil
}

// Restore restores a snapshot of the storage.
func (st *meshStorage) Restore(ctx context.Context, r io.Reader) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	kvdata, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("memory restore: %w", err)
	}
	var data v1.RaftSnapshot
	if err := proto.Unmarshal(kvdata, &data); err != nil {
		return fmt.Errorf("memory restore: %w", err)
	}
	st.data = make(map[string]dataItem)
	for k, v := range data.Kv {
		key := k
		val := v
		st.data[key] = dataItem{
			value: val.Value,
			ttl: func() time.Time {
				if val.Ttl == nil || val.Ttl.AsDuration() == 0 {
					return time.Time{}
				}
				return time.Now().Add(val.Ttl.AsDuration())
			}(),
		}
	}
	return nil
}

// Subscribe will call the given function whenever a key with the given prefix is changed.
// The returned function can be called to unsubscribe.
func (st *meshStorage) Subscribe(ctx context.Context, prefix string, fn storage.SubscribeFunc) (context.CancelFunc, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("memory subscribe: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	st.subs[id.String()] = subscription{
		prefix: prefix,
		fn:     fn,
		ctx:    ctx,
		cancel: cancel,
	}
	return cancel, nil
}

// Close closes the storage.
func (st *meshStorage) Close() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, sub := range st.subs {
		sub.cancel()
	}
	return nil
}
