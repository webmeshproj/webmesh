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

package plugindb

import (
	"fmt"
	"strings"
	"sync"
	"time"

	v1 "github.com/webmeshproj/api/go/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// OpenKeyVal opens a new key-value store connection to a plugin query stream.
func OpenKeyVal(srv QueryServer) storage.MeshStorage {
	return &PluginMeshStorage{QueryServer: srv}
}

// PluginMeshStorage implements a mesh key-value store over a plugin query stream.
type PluginMeshStorage struct {
	QueryServer
	mu sync.Mutex
}

// GetValue returns the value of a key.
func (p *PluginMeshStorage) GetValue(ctx context.Context, key []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !types.IsValidPathID(string(key)) {
		return nil, errors.ErrInvalidKey
	}
	err := p.Send(&v1.QueryRequest{
		Command: v1.QueryRequest_GET,
		Type:    v1.QueryRequest_VALUE,
		Query:   types.NewQueryFilters().WithID(string(key)).Encode(),
	})
	if err != nil {
		return nil, err
	}
	resp, err := p.Recv()
	if err != nil {
		return nil, err
	}
	if resp.GetError() != "" {
		if strings.Contains(err.Error(), "not found") {
			return nil, errors.ErrKeyNotFound
		}
		return nil, fmt.Errorf(resp.GetError())
	}
	if len(resp.GetItems()) == 0 {
		return nil, errors.ErrKeyNotFound
	}
	return resp.GetItems()[0], nil
}

func (p *PluginMeshStorage) PutValue(ctx context.Context, key, value []byte, ttl time.Duration) error {
	return errors.ErrNotStorageNode
}

func (p *PluginMeshStorage) Delete(ctx context.Context, key []byte) error {
	return errors.ErrNotStorageNode
}

func (p *PluginMeshStorage) ListKeys(ctx context.Context, prefix []byte) ([][]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	err := p.Send(&v1.QueryRequest{
		Command: v1.QueryRequest_LIST,
		Type:    v1.QueryRequest_KEYS,
		Query:   types.NewQueryFilters().WithID(string(prefix)).Encode(),
	})
	if err != nil {
		return nil, err
	}
	resp, err := p.Recv()
	if err != nil {
		return nil, err
	}
	return resp.GetItems(), nil
}

func (p *PluginMeshStorage) IterPrefix(ctx context.Context, prefix []byte, fn storage.PrefixIterator) error {
	keys, err := p.ListKeys(ctx, prefix)
	if err != nil {
		return err
	}
	for _, key := range keys {
		value, err := p.GetValue(ctx, key)
		if err != nil {
			return err
		}
		if err := fn(key, value); err != nil {
			return err
		}
	}
	return nil
}

func (p *PluginMeshStorage) Subscribe(ctx context.Context, prefix []byte, fn storage.KVSubscribeFunc) (context.CancelFunc, error) {
	return func() {}, errors.ErrNotStorageNode
}

func (p *PluginMeshStorage) Close() error {
	return nil
}
