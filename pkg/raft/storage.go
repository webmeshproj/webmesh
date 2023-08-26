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

package raft

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/golang/snappy"
	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	raftbadger "github.com/webmeshproj/raft-badger"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/badger"
)

// MarshalLogEntry marshals a RaftLogEntry.
func MarshalLogEntry(logEntry *v1.RaftLogEntry) ([]byte, error) {
	data, err := proto.Marshal(logEntry)
	if err == nil {
		data = snappy.Encode(nil, data)
	}
	if err != nil {
		return nil, fmt.Errorf("encode log entry: %w", err)
	}
	return data, nil
}

// UnmarshalLogEntry unmarshals a RaftLogEntry.
func UnmarshalLogEntry(data []byte) (*v1.RaftLogEntry, error) {
	data, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, fmt.Errorf("decode log entry: %w", err)
	}
	logEntry := &v1.RaftLogEntry{}
	if err := proto.Unmarshal(data, logEntry); err != nil {
		return nil, fmt.Errorf("unmarshal log entry: %w", err)
	}
	return logEntry, nil
}

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

// MemoryStore is a Store that is in-memory.
type MemoryStore interface {
	LogStoreCloser
	StableStoreCloser
}

var _ = raft.MonotonicLogStore(&MonotonicLogStore{})

// MonotonicLogStore is a LogStore that is monotonic.
type MonotonicLogStore struct {
	raft.LogStore
}

// IsMonotonic returns true if the log store is monotonic.
func (m *MonotonicLogStore) IsMonotonic() bool {
	return true
}

// NewInmemStore returns a new in-memory store that can be used
// for logs and stable storage.
func NewInmemStore() MemoryStore {
	return &inMemoryCloser{raft.NewInmemStore()}
}

type inMemoryCloser struct {
	*raft.InmemStore
}

func (i *inMemoryCloser) Close() error {
	return nil
}

func (r *raftNode) createDataStores(ctx context.Context) error {
	if r.opts.InMemory {
		var err error
		raftstore := NewInmemStore()
		r.logDB = raftstore
		r.stableDB = raftstore
		r.raftSnapshots = raft.NewInmemSnapshotStore()
		r.dataDB, err = badger.New(&storage.Options{InMemory: true})
		if err != nil {
			err = fmt.Errorf("new inmem storage: %w", err)
		}
		return err
	}
	storePath := r.opts.StorePath()
	raftstore, err := raftbadger.New(r.log.With("component", "raftbadger"), storePath)
	if err != nil {
		return fmt.Errorf("new raft badger: %w", err)
	}
	r.logDB = raftstore
	r.stableDB = raftstore
	r.raftSnapshots, err = raft.NewFileSnapshotStoreWithLogger(
		r.opts.DataDir,
		int(r.opts.SnapshotRetention),
		&hclogAdapter{
			Logger: r.log.With("component", "snapshotstore"),
			level:  r.opts.LogLevel,
		},
	)
	handleErr := func(cause error) error {
		defer func() {
			if err := raftstore.Close(); err != nil {
				r.log.Error("failed to close raftbadger store", slog.String("error", err.Error()))
			}
		}()
		return cause
	}
	if err != nil {
		return handleErr(fmt.Errorf("new file snapshot store: %w", err))
	}
	r.dataDB, err = badger.New(&storage.Options{
		DiskPath: r.opts.DataStoragePath(),
	})
	if err != nil {
		return handleErr(fmt.Errorf("new disk storage: %w", err))
	}
	return nil
}

func (r *raftNode) closeDataStores(ctx context.Context) {
	for name, closer := range map[string]io.Closer{
		"raft transport": r.raftTransport,
		"data database":  r.dataDB,
		"raft log db":    r.logDB,
	} {
		r.log.Debug("closing " + name)
		if err := closer.Close(); err != nil {
			r.log.Error("error closing "+name, slog.String("error", err.Error()))
		}
	}
}

// raftStorage wraps the storage.Storage interface to force write operations through the Raft log.
type raftStorage struct {
	storage.Storage
	raft *raftNode
}

// Put sets the value of a key.
func (rs *raftStorage) Put(ctx context.Context, key, value string, ttl time.Duration) error {
	if !rs.raft.IsVoter() {
		return ErrNotVoter
	}
	logEntry := v1.RaftLogEntry{
		Type:  v1.RaftCommandType_PUT,
		Key:   key,
		Value: value,
		Ttl:   durationpb.New(ttl),
	}
	if rs.raft.IsLeader() {
		// lock is taken in the FSM
		return rs.applyLog(ctx, &logEntry)
	}
	// We need to forward the request to the leader.
	return rs.sendLogToLeader(ctx, &logEntry)
}

// Delete removes a key.
func (rs *raftStorage) Delete(ctx context.Context, key string) error {
	if !rs.raft.IsVoter() {
		return ErrNotVoter
	}
	logEntry := v1.RaftLogEntry{
		Type: v1.RaftCommandType_DELETE,
		Key:  key,
	}
	if rs.raft.IsLeader() {
		// lock is taken in the FSM
		return rs.applyLog(ctx, &logEntry)
	}
	// We need to forward the request to the leader.
	return rs.sendLogToLeader(ctx, &logEntry)
}

// Snapshot returns a snapshot of the storage.
func (rs *raftStorage) Snapshot(ctx context.Context) (io.Reader, error) {
	return nil, errors.New("not implemented")
}

// Restore restores a snapshot of the storage.
func (rs *raftStorage) Restore(ctx context.Context, r io.Reader) error {
	return errors.New("not implemented")
}

func (rs *raftStorage) sendLogToLeader(ctx context.Context, logEntry *v1.RaftLogEntry) error {
	log := context.LoggerFrom(ctx)
	log.Debug("sending log to leader")
	c, err := rs.raft.leaderDialer.DialLeader(ctx)
	if err != nil {
		return fmt.Errorf("dial leader: %w", err)
	}
	defer c.Close()
	cli := v1.NewMembershipClient(c)
	resp, err := cli.Apply(ctx, logEntry)
	if err != nil {
		return fmt.Errorf("apply log entry: %w", err)
	}
	log.Debug("applied log entry", slog.String("time", resp.GetTime()))
	if resp.GetError() != "" {
		return fmt.Errorf("apply log entry: %s", resp.GetError())
	}
	return nil
}

func (rs *raftStorage) applyLog(ctx context.Context, logEntry *v1.RaftLogEntry) error {
	defer func() {
		timeout := rs.raft.opts.ApplyTimeout
		if deadline, ok := ctx.Deadline(); ok {
			timeout = time.Until(deadline)
		}
		err := rs.raft.Raft().Barrier(timeout).Error()
		if err != nil {
			rs.raft.log.Error("barrier error", slog.String("error", err.Error()))
		}
	}()
	timeout := rs.raft.opts.ApplyTimeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	data, err := MarshalLogEntry(logEntry)
	if err != nil {
		return fmt.Errorf("marshal log entry: %w", err)
	}
	f := rs.raft.Raft().Apply(data, timeout)
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
