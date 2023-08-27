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

// Package plugindb contains a SQL driver for running data queries over a Plugin
// Query stream.
package plugindb

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/storage"
)

// Open opens a new database connection to a plugin query stream.
func Open(srv v1.Plugin_InjectQuerierServer) storage.MeshStorage {
	return &pluginDB{srv: srv}
}

type pluginDB struct {
	srv v1.Plugin_InjectQuerierServer
	// TODO: Add a multiplexer to allow multiple queries at once?
	mu sync.Mutex
}

func (p *pluginDB) GetValue(ctx context.Context, key string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	req := &v1.PluginQuery{
		Id:      id.String(),
		Command: v1.PluginQuery_GET,
		Query:   key,
	}
	if err := p.srv.Send(req); err != nil {
		return "", err
	}
	resp, err := p.srv.Recv()
	if err != nil {
		return "", err
	}
	if len(resp.GetValue()) == 0 {
		// This should never happen, but just in case.
		return "", storage.ErrKeyNotFound
	}
	return resp.GetValue()[0], nil
}

// Put sets the value of a key.
func (p *pluginDB) PutValue(ctx context.Context, key, value string, ttl time.Duration) error {
	return errors.New("put not implemented")
}

// Delete removes a key.
func (p *pluginDB) Delete(ctx context.Context, key string) error {
	return errors.New("delete not implemented")
}

// List returns all keys with a given prefix.
func (p *pluginDB) List(ctx context.Context, prefix string) ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	req := &v1.PluginQuery{
		Id:      id.String(),
		Command: v1.PluginQuery_LIST,
		Query:   prefix,
	}
	if err := p.srv.Send(req); err != nil {
		return nil, err
	}
	resp, err := p.srv.Recv()
	if err != nil {
		return nil, err
	}
	return resp.GetValue(), nil
}

// IterPrefix iterates over all keys with a given prefix.
func (p *pluginDB) IterPrefix(ctx context.Context, prefix string, fn storage.PrefixIterator) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	id, err := uuid.NewRandom()
	if err != nil {
		return err
	}
	req := &v1.PluginQuery{
		Id:      id.String(),
		Command: v1.PluginQuery_ITER,
		Query:   prefix,
	}
	if err := p.srv.Send(req); err != nil {
		return err
	}
	for {
		resp, err := p.srv.Recv()
		if err != nil {
			return err
		}
		if resp.GetError() == "EOF" {
			return nil
		}
		if len(resp.GetValue()) == 0 {
			// Should never happen, silently continue.
			continue
		}
		if err := fn(resp.GetKey(), resp.GetValue()[0]); err != nil {
			return err
		}
	}
}

// Snapshot returns a snapshot of the storage.
func (p *pluginDB) Snapshot(ctx context.Context) (io.Reader, error) {
	return nil, errors.New("snapshot not implemented")
}

// Restore restores a snapshot of the storage.
func (p *pluginDB) Restore(ctx context.Context, r io.Reader) error {
	return errors.New("restore not implemented")
}

// Subscribe will call the given function whenever a key with the given prefix is changed.
// The returned function can be called to unsubscribe.
func (p *pluginDB) Subscribe(ctx context.Context, prefix string, fn storage.SubscribeFunc) (context.CancelFunc, error) {
	return nil, errors.New("subscribe not implemented")
}

// Close closes the storage.
func (p *pluginDB) Close() error {
	return nil
}
