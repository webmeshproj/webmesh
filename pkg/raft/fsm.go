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
	"fmt"
	"io"
	"time"

	"github.com/golang/snappy"
	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/protobuf/proto"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb/raftlogs"
)

// Snapshot returns a Raft snapshot.
func (r *raftNode) Snapshot() (raft.FSMSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// TODO: Set a timeout on this.
	return r.snapshotter.Snapshot(context.Background())
}

// Restore restores a Raft snapshot.
func (r *raftNode) Restore(rdr io.ReadCloser) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	// TODO: Set a timeout on this.
	return r.snapshotter.Restore(context.Background(), rdr)
}

// ApplyBatch implements the raft.BatchingFSM interface.
func (r *raftNode) ApplyBatch(logs []*raft.Log) []any {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log.Debug("applying batch", slog.Int("count", len(logs)))
	res := make([]any, len(logs))
	for i, l := range logs {
		res[i] = r.applyLog(l)
	}
	return res
}

// Apply applies a Raft log entry to the store.
func (r *raftNode) Apply(l *raft.Log) any {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.applyLog(l)
}

func (r *raftNode) applyLog(l *raft.Log) (res any) {
	log := r.log.With(slog.Int("index", int(l.Index)), slog.Int("term", int(l.Term)))
	log.Debug("applying log", "type", l.Type.String())
	start := time.Now()
	defer func() {
		log.Debug("finished applying log", slog.String("took", time.Since(start).String()))
	}()
	defer r.lastAppliedIndex.Store(l.Index)
	defer r.currentTerm.Store(l.Term)

	// Validate the term/index of the log entry.
	dbTerm := r.currentTerm.Load()
	dbIndex := r.lastAppliedIndex.Load()
	log.Debug("last applied index",
		slog.Int("last-term", int(dbTerm)),
		slog.Int("last-index", int(dbIndex)))

	if l.Term < dbTerm {
		log.Debug("received log from old term")
		return &v1.RaftApplyResponse{
			Time: time.Since(start).String(),
		}
	} else if l.Index <= dbIndex {
		log.Debug("log already applied to database")
		return &v1.RaftApplyResponse{
			Time: time.Since(start).String(),
		}
	}

	if l.Type != raft.LogCommand {
		// We only care about command logs.
		return &v1.RaftApplyResponse{
			Time: time.Since(start).String(),
		}
	}

	// Decode the log entry
	var cmd v1.RaftLogEntry
	decoded, err := snappy.Decode(nil, l.Data)
	if err == nil {
		err = proto.Unmarshal(decoded, &cmd)
	}
	if err != nil {
		// This is a fatal error. We can't apply the log entry if we can't
		// decode it. This should never happen.
		log.Error("error decoding raft log entry", slog.String("error", err.Error()))
		return &v1.RaftApplyResponse{
			Time:  time.Since(start).String(),
			Error: fmt.Sprintf("decode log entry: %s", err.Error()),
		}
	}

	var ctx context.Context
	var cancel context.CancelFunc
	if r.opts.ApplyTimeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), r.opts.ApplyTimeout)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()
	ctx = context.WithLogger(ctx, log)

	if r.opts.OnApplyLog != nil {
		// Call the OnApplyLog callback in a goroutine to not block the local storage.
		go r.opts.OnApplyLog(ctx, l.Term, l.Index, &cmd)
	}
	// Apply the log entry to the database.
	return raftlogs.Apply(ctx, r.dataDB, &cmd)
}
