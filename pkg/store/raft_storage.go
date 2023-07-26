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

package store

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/golang/snappy"
	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/proto"

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/storage"
)

// LogStoreCloser is a LogStore that can be closed.
type LogStoreCloser interface {
	io.Closer
	raft.LogStore
}

// StableStoreCloser is a StableStore that can be closed.
type StableStoreCloser interface {
	io.Closer
	raft.StableStore
}

// raftStorage wraps the storage.Storage interface to force write operations through the Raft log.
type raftStorage struct {
	storage.Storage
	store *store
}

// Put sets the value of a key.
func (rs *raftStorage) Put(ctx context.Context, key, value string) error {
	logEntry := &v1.RaftLogEntry{
		Type:  v1.RaftCommandType_PUT,
		Key:   key,
		Value: value,
	}
	return rs.sendLog(ctx, logEntry)
}

// Delete removes a key.
func (rs *raftStorage) Delete(ctx context.Context, key string) error {
	logEntry := &v1.RaftLogEntry{
		Type: v1.RaftCommandType_DELETE,
		Key:  key,
	}
	return rs.sendLog(ctx, logEntry)
}

// Snapshot returns a snapshot of the storage.
func (rs *raftStorage) Snapshot(ctx context.Context) (io.Reader, error) {
	return nil, errors.New("not implemented")
}

// Restore restores a snapshot of the storage.
func (rs *raftStorage) Restore(ctx context.Context, r io.Reader) error {
	return errors.New("not implemented")
}

func (rs *raftStorage) sendLog(ctx context.Context, logEntry *v1.RaftLogEntry) error {
	timeout := rs.store.opts.Raft.ApplyTimeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	data, err := marshalLogEntry(logEntry)
	if err != nil {
		return fmt.Errorf("marshal log entry: %w", err)
	}
	f := rs.store.raft.Apply(data, timeout)
	if err := f.Error(); err != nil {
		if errors.Is(err, raft.ErrNotLeader) {
			return ErrNotLeader
		}
		return fmt.Errorf("apply log entry: %w", err)
	}
	resp := f.Response().(*v1.RaftApplyResponse)
	if resp.GetError() != "" {
		return fmt.Errorf("apply log entry data: %s", resp.GetError())
	}
	return nil
}

func marshalLogEntry(logEntry *v1.RaftLogEntry) ([]byte, error) {
	data, err := proto.Marshal(logEntry)
	if err == nil {
		data = snappy.Encode(nil, data)
	}
	if err != nil {
		return nil, fmt.Errorf("encode log entry: %w", err)
	}
	return data, nil
}

type monotonicLogStore struct{ raft.LogStore }

var _ = raft.MonotonicLogStore(&monotonicLogStore{})

func (m *monotonicLogStore) IsMonotonic() bool {
	return true
}

func newInmemStore() *inMemoryCloser {
	return &inMemoryCloser{raft.NewInmemStore()}
}

type inMemoryCloser struct {
	*raft.InmemStore
}

func (i *inMemoryCloser) Close() error {
	return nil
}
