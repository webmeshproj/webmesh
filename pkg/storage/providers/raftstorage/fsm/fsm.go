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

// Package fsm implements the Raft FSM.
package fsm

import (
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang/snappy"
	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/protobuf/proto"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/providers/raftstorage/raftlogs"
	"github.com/webmeshproj/webmesh/pkg/storage/providers/raftstorage/snapshots"
)

// Ensure that RaftFSM implements the raft.FSM interface.
var _ raft.FSM = &RaftFSM{}

// RaftFSM is the Raft FSM.
type RaftFSM struct {
	currentTerm      atomic.Uint64
	lastAppliedIndex atomic.Uint64
	opts             Options
	store            storage.MeshStorage
	snapshotter      snapshots.Snapshotter
	log              *slog.Logger
	mu               sync.Mutex
}

// Options are options for the FSM.
type Options struct {
	// ApplyTimeout is the timeout for applying a log entry.
	ApplyTimeout time.Duration
}

// New returns a new RaftFSM. The storage interface must be a direct
// connection to the underlying database.
func New(ctx context.Context, st storage.DualStorage, opts Options) *RaftFSM {
	return &RaftFSM{
		store:       st,
		opts:        opts,
		log:         context.LoggerFrom(ctx).With("component", "raft-fsm"),
		snapshotter: snapshots.New(ctx, st),
	}
}

// LastAppliedIndex returns the last applied index.
func (r *RaftFSM) LastAppliedIndex() uint64 {
	return r.lastAppliedIndex.Load()
}

// CurrentTerm returns the current term.
func (r *RaftFSM) CurrentTerm() uint64 {
	return r.currentTerm.Load()
}

// Snapshot returns a Raft snapshot.
func (r *RaftFSM) Snapshot() (raft.FSMSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// TODO: Set a timeout on this.
	return r.snapshotter.Snapshot(context.Background())
}

// Restore restores a Raft snapshot.
func (r *RaftFSM) Restore(rdr io.ReadCloser) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	// TODO: Set a timeout on this.
	err := r.snapshotter.Restore(context.Background(), rdr)
	if err != nil {
		return fmt.Errorf("restore snapshot: %w", err)
	}
	return nil
}

// ApplyBatch implements the raft.BatchingFSM interface.
func (r *RaftFSM) ApplyBatch(logs []*raft.Log) []any {
	r.mu.Lock()
	r.log.Debug("Applying batch", slog.Int("count", len(logs)))
	res := make([]any, len(logs))
	for i, l := range logs {
		_, res[i] = r.applyLog(l)
	}
	r.mu.Unlock()
	return res
}

// Apply applies a Raft log entry to the store.
func (r *RaftFSM) Apply(l *raft.Log) any {
	r.mu.Lock()
	_, res := r.applyLog(l)
	r.mu.Unlock()
	return res
}

func (r *RaftFSM) applyLog(l *raft.Log) (cmd *v1.RaftLogEntry, res *v1.RaftApplyResponse) {
	log := r.log.With(slog.Int("index", int(l.Index)), slog.Int("term", int(l.Term)))
	log.Debug("applying log", "type", l.Type.String())
	start := time.Now()
	defer func() {
		log.Debug("Finished applying log", slog.String("took", time.Since(start).String()))
	}()

	// Validate the term/index of the log entry.
	dbTerm := r.currentTerm.Load()
	dbIndex := r.lastAppliedIndex.Load()
	log.Debug("Last applied index", slog.Int("last-term", int(dbTerm)), slog.Int("last-index", int(dbIndex)))

	if l.Term < dbTerm {
		log.Debug("Received log from old term")
		return nil, &v1.RaftApplyResponse{
			Time: time.Since(start).String(),
		}
	} else if l.Index <= dbIndex {
		log.Debug("Log already applied to database")
		return nil, &v1.RaftApplyResponse{
			Time: time.Since(start).String(),
		}
	}

	defer r.lastAppliedIndex.Store(l.Index)
	defer r.currentTerm.Store(l.Term)

	if l.Type != raft.LogCommand {
		// We only care about command logs.
		return nil, &v1.RaftApplyResponse{
			Time: time.Since(start).String(),
		}
	}

	// Decode the log entry
	cmd, err := UnmarshalLogEntry(l.Data)
	if err != nil {
		// This is a fatal error. We can't apply the log entry if we can't
		// decode it. This should never happen.
		log.Error("Error decoding raft log entry", slog.String("error", err.Error()))
		return nil, &v1.RaftApplyResponse{
			Time:  time.Since(start).String(),
			Error: fmt.Sprintf("decode log entry: %s", err.Error()),
		}
	}
	log.Debug("Applying log entry", slog.String("command", cmd.String()))

	var ctx context.Context
	var cancel context.CancelFunc
	if r.opts.ApplyTimeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), r.opts.ApplyTimeout)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()
	ctx = context.WithLogger(ctx, log)

	// Apply the log entry to the database.
	return cmd, raftlogs.Apply(ctx, r.store, cmd)
}

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
