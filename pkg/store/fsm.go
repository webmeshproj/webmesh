/*
Copyright 2023.

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
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/hashicorp/raft"
	v1 "gitlab.com/webmesh/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/protobuf/proto"

	"gitlab.com/webmesh/node/pkg/db"
)

// ApplyBatch implements the raft.BatchingFSM interface.
func (s *store) ApplyBatch(logs []*raft.Log) []any {
	s.log.Debug("applying batch", slog.Int("count", len(logs)))
	res := make([]any, len(logs))
	for i, l := range logs {
		res[i] = s.Apply(l)
	}
	return res
}

// Apply applies a Raft log entry to the store.
func (s *store) Apply(l *raft.Log) any {
	log := s.log.With(slog.Int("index", int(l.Index)), slog.Int("term", int(l.Term)))
	log.Debug("applying log")
	start := time.Now()
	defer func() {
		log.Debug("finished applying log", slog.String("took", time.Since(start).String()))
	}()
	defer s.raftIndex.Store(l.Index)

	dbTerm, dbIndex, err := s.getDBTermAndIndex(l)
	if err != nil {
		// This is a fatal error. We need to check the term and index of the
		// log entry against the database, but if we can't do that, we can't
		// apply the log entry.
		// TODO: This should trigger some sort of recovery.
		log.Error("error checking last applied index", slog.String("error", err.Error()))
		return &v1.RaftApplyResponse{
			Time: time.Since(start).String(),
			Result: &v1.RaftApplyResponse_Error{
				Error: fmt.Sprintf("check last applied index: %s", err.Error()),
			},
		}
	}

	if l.Term < dbTerm {
		log.Debug("received log from old term")
		return &v1.RaftApplyResponse{
			Time: time.Since(start).String(),
		}
	} else if l.Term > dbTerm {
		// This is a new term. We need to update the current term in the
		// database.
		log.Debug("new epoch, updating current term in db")
		q := db.New(s.data)
		err := q.SetCurrentRaftTerm(context.Background(), strconv.Itoa(int(l.Term)))
		if err != nil {
			// Same as above, this is a fatal error that needs to be handled.
			log.Error("error updating current term", slog.String("error", err.Error()))
			return &v1.RaftApplyResponse{
				Time: time.Since(start).String(),
				Result: &v1.RaftApplyResponse_Error{
					Error: fmt.Sprintf("update current term: %s", err.Error()),
				},
			}
		}

	} else if l.Index <= dbIndex {
		log.Debug("log already applied to database")
		return &v1.RaftApplyResponse{
			Time: time.Since(start).String(),
		}
	}

	defer func() {
		q := db.New(s.data)
		if dbIndex != l.Index {
			log.Debug("updating last applied index in db")
			err := q.SetLastAppliedRaftIndex(context.Background(), strconv.Itoa(int(l.Index)))
			if err != nil {
				// We'll live. This isn't a fatal error, but it's not great.
				// Next boot will just have to replay the log entries and might
				// have some local constraint errors.
				log.Error("error updating last applied index", slog.String("error", err.Error()))
			}
		}
	}()

	if l.Type != raft.LogCommand {
		log.Debug("not a data query log", slog.String("type", l.Type.String()))
		return &v1.RaftApplyResponse{
			Time: time.Since(start).String(),
		}
	}

	var cmd v1.RaftLogEntry
	err = proto.Unmarshal(l.Data, &cmd)
	if err != nil {
		// This is a fatal error. We can't apply the log entry if we can't
		// decode it. This should never happen.
		log.Error("error decoding raft log entry", slog.String("error", err.Error()))
		return &v1.RaftApplyResponse{
			Time: time.Since(start).String(),
			Result: &v1.RaftApplyResponse_Error{
				Error: fmt.Sprintf("unmarshal raft log entry: %s", err.Error()),
			},
		}
	}

	return s.apply(l, &cmd, log, start)
}

// Snapshot returns a Raft snapshot.
func (s *store) Snapshot() (raft.FSMSnapshot, error) {
	return s.newSnapshot()
}

// Restore restores a Raft snapshot.
func (s *store) Restore(r io.ReadCloser) error {
	s.log.Debug("restoring snapshot")
	start := time.Now()
	defer func() {
		s.log.Debug("finished restoring snapshot", slog.String("took", time.Since(start).String()))
	}()
	defer r.Close()
	s.dataMux.Lock()
	defer s.dataMux.Unlock()
	// Close the database if it's open.
	if s.data != nil {
		err := s.data.Close()
		if err != nil {
			return fmt.Errorf("close data file: %w", err)
		}
	}
	f, err := os.OpenFile(s.opts.DataFilePath(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open data file for writing: %w", err)
	}
	defer f.Close()
	// Decompress the data from the snapshot.
	zr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("create gzip reader: %w", err)
	}
	defer zr.Close()
	if _, err := io.Copy(f, zr); err != nil {
		return fmt.Errorf("decompress data file: %w", err)
	}
	// Re-open the database.
	s.data, err = sql.Open("sqlite", s.opts.DataFilePath())
	return err
}

// newSnapshot creates a new Raft snapshot.
func (s *store) newSnapshot() (raft.FSMSnapshot, error) {
	s.log.Debug("creating new snapshot")
	start := time.Now()
	s.dataMux.Lock()
	defer s.dataMux.Unlock()
	f, err := os.Open(s.opts.DataFilePath())
	if err != nil {
		return nil, fmt.Errorf("open data file for reading: %w", err)
	}
	defer f.Close()
	// Compress the data to in-memory buffer.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	defer zw.Close()
	if _, err := io.Copy(zw, f); err != nil {
		return nil, fmt.Errorf("compress data file: %w", err)
	}
	s.log.Debug("created new snapshot",
		slog.Int("size", buf.Len()),
		slog.String("took", time.Since(start).String()))
	// Return the snapshot.
	return &snapshot{data: &buf, log: s.log}, nil
}

// snapshot is a Raft snapshot.
type snapshot struct {
	data *bytes.Buffer
	log  *slog.Logger
}

// Persist persists the snapshot to a sink.
func (s *snapshot) Persist(sink raft.SnapshotSink) error {
	defer sink.Close()
	if s.data == nil {
		return fmt.Errorf("snapshot data is nil")
	}
	s.log.Debug("persisting snapshot", slog.Int("size", s.data.Len()))
	var buf bytes.Buffer
	if _, err := io.Copy(sink, io.TeeReader(s.data, &buf)); err != nil {
		return fmt.Errorf("write snapshot data to sink: %w", err)
	}
	s.data = &buf
	return nil
}

// Release releases the snapshot.
func (s *snapshot) Release() {
	s.log.Debug("releasing snapshot")
	s.data.Reset()
	s.data = nil
}

func (s *store) getDBTermAndIndex(l *raft.Log) (term, index uint64, err error) {
	// Check if the current term and index is already applied.
	raftState, err := db.New(s.data).GetRaftState(context.Background())
	if err != nil {
		err = fmt.Errorf("get raft state: %w", err)
		return
	}
	var raftTerm, raftIndex uint64
	termStr := raftState.CurrentRaftTerm.(string)
	indexStr := raftState.LastAppliedRaftIndex.(string)
	if raftState.CurrentRaftTerm != "" {
		raftTerm, err = strconv.ParseUint(termStr, 10, 64)
		if err != nil {
			err = fmt.Errorf("parse raft term: %w", err)
			return
		}
	}
	if raftState.LastAppliedRaftIndex != "" {
		raftIndex, err = strconv.ParseUint(indexStr, 10, 64)
		if err != nil {
			err = fmt.Errorf("parse raft index: %w", err)
			return
		}
	}
	return raftTerm, raftIndex, nil
}
