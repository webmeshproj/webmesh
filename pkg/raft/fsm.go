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
	"log/slog"
	"time"

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb/raftlogs"
)

var _ raft.FSM = &raftNodeFSM{}

type raftNodeFSM struct {
	raftNode *raftNode
}

// Snapshot returns a Raft snapshot.
func (r *raftNodeFSM) Snapshot() (raft.FSMSnapshot, error) {
	r.raftNode.mu.Lock()
	defer r.raftNode.mu.Unlock()
	// TODO: Set a timeout on this.
	return r.raftNode.snapshotter.Snapshot(context.Background())
}

// Restore restores a Raft snapshot.
func (r *raftNodeFSM) Restore(rdr io.ReadCloser) error {
	r.raftNode.mu.Lock()
	defer r.raftNode.mu.Unlock()
	// TODO: Set a timeout on this.
	return r.raftNode.snapshotter.Restore(context.Background(), rdr)
}

// ApplyBatch implements the raft.BatchingFSM interface.
func (r *raftNodeFSM) ApplyBatch(logs []*raft.Log) []any {
	r.raftNode.mu.Lock()
	defer r.raftNode.mu.Unlock()
	r.raftNode.log.Debug("applying batch", slog.Int("count", len(logs)))
	res := make([]any, len(logs))
	for i, l := range logs {
		res[i] = r.applyLog(l)
	}
	return res
}

// Apply applies a Raft log entry to the store.
func (r *raftNodeFSM) Apply(l *raft.Log) any {
	r.raftNode.mu.Lock()
	defer r.raftNode.mu.Unlock()
	return r.applyLog(l)
}

func (r *raftNodeFSM) applyLog(l *raft.Log) (res any) {
	log := r.raftNode.log.With(slog.Int("index", int(l.Index)), slog.Int("term", int(l.Term)))
	log.Debug("applying log", "type", l.Type.String())
	start := time.Now()
	defer func() {
		log.Debug("finished applying log", slog.String("took", time.Since(start).String()))
	}()
	defer r.raftNode.lastAppliedIndex.Store(l.Index)
	defer r.raftNode.currentTerm.Store(l.Term)

	// Validate the term/index of the log entry.
	dbTerm := r.raftNode.currentTerm.Load()
	dbIndex := r.raftNode.lastAppliedIndex.Load()
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
	cmd, err := UnmarshalLogEntry(l.Data)
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
	if r.raftNode.opts.ApplyTimeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), r.raftNode.opts.ApplyTimeout)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()
	ctx = context.WithLogger(ctx, log)

	if r.raftNode.opts.OnApplyLog != nil {
		// Call the OnApplyLog callback in a goroutine to not block the local storage.
		go r.raftNode.opts.OnApplyLog(ctx, l.Term, l.Index, cmd)
	}
	// Apply the log entry to the database.
	return raftlogs.Apply(ctx, r.raftNode.meshDB, cmd)
}
