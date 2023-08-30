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

// Package snapshots provides an interface for managing raft snapshots.
package snapshots

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/hashicorp/raft"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// Snapshotter is an interface for taking and restoring snapshots.
type Snapshotter interface {
	// Snapshot returns a new snapshot.
	Snapshot(ctx context.Context) (raft.FSMSnapshot, error)
	// Restore restores a snapshot.
	Restore(ctx context.Context, r io.ReadCloser) error
}

type snapshotter struct {
	st  storage.MeshStorage
	log *slog.Logger
}

// New returns a new Snapshotter.
func New(ctx context.Context, st storage.MeshStorage) Snapshotter {
	return &snapshotter{
		st:  st,
		log: context.LoggerFrom(ctx).With("component", "snapshots"),
	}
}

func (s *snapshotter) Snapshot(ctx context.Context) (raft.FSMSnapshot, error) {
	s.log.Info("creating new db snapshot")
	start := time.Now()
	data, err := s.st.Snapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("get snapshot: %w", err)
	}
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	if _, err := io.Copy(gzw, data); err != nil {
		return nil, fmt.Errorf("compress snapshot data: %w", err)
	}
	if err := gzw.Close(); err != nil {
		return nil, fmt.Errorf("close gzip writer: %w", err)
	}
	snapshot := &snapshot{&buf}
	s.log.Info("db snapshot complete",
		slog.String("duration", time.Since(start).String()),
		slog.String("size", snapshot.size()),
	)
	return snapshot, nil
}

func (s *snapshotter) Restore(ctx context.Context, r io.ReadCloser) error {
	defer r.Close()
	s.log.Info("restoring db snapshot")
	start := time.Now()
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gzr.Close()
	data, err := io.ReadAll(gzr)
	if err != nil {
		return fmt.Errorf("read snapshot: %w", err)
	}
	if err := s.st.Restore(ctx, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("restore snapshot: %w", err)
	}
	s.log.Info("db snapshot restore complete", slog.String("duration", time.Since(start).String()))
	return nil
}

// snapshot is a Raft snapshot.
type snapshot struct {
	data *bytes.Buffer
}

// Persist persists the snapshot to a sink.
func (s *snapshot) Persist(sink raft.SnapshotSink) error {
	defer sink.Close()
	if s.data == nil {
		return fmt.Errorf("snapshot data is nil")
	}
	var buf bytes.Buffer
	if _, err := io.Copy(sink, io.TeeReader(s.data, &buf)); err != nil {
		return fmt.Errorf("write snapshot data to sink: %w", err)
	}
	s.data = &buf
	return nil
}

// Release releases the snapshot.
func (s *snapshot) Release() {
	s.data.Reset()
	s.data = nil
}

func (s *snapshot) size() string {
	b := int64(s.data.Len())
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB",
		float64(b)/float64(div), "KMGTPE"[exp])
}
