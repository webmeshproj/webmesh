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
	"context"
	"database/sql"
	"fmt"
	"io"
	"time"

	"github.com/hashicorp/raft"
	"github.com/mattn/go-sqlite3"
	"golang.org/x/exp/slog"
)

// Snapshotter is an interface for taking and restoring snapshots.
type Snapshotter interface {
	// Snapshot returns a new snapshot.
	Snapshot(ctx context.Context) (raft.FSMSnapshot, error)
	// Restore restores a snapshot.
	Restore(ctx context.Context, r io.ReadCloser) error
}

type snapshotter struct {
	db  *sql.DB
	log *slog.Logger
}

// New returns a new Snapshotter.
func New(db *sql.DB) Snapshotter {
	return &snapshotter{
		db:  db,
		log: slog.Default().With("component", "snapshots"),
	}
}

const schema = "main"

func (s *snapshotter) Snapshot(ctx context.Context) (raft.FSMSnapshot, error) {
	s.log.Info("creating new db snapshot")
	start := time.Now()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("get db connection: %w", err)
	}
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	err = conn.Raw(func(driverConn interface{}) error {
		sqliteConn, ok := driverConn.(*sqlite3.SQLiteConn)
		if !ok {
			return fmt.Errorf("expected sqlite3 connection, got %T", conn)
		}
		out, err := sqliteConn.Serialize(schema)
		if err != nil {
			return fmt.Errorf("serialize db: %w", err)
		}
		if _, err := gzw.Write(out); err != nil {
			return fmt.Errorf("write db: %w", err)
		}
		return gzw.Close()
	})
	if err != nil {
		return nil, fmt.Errorf("snapshot db: %w", err)
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
	// Create an in-memory database to deserialize the backup into.
	restore, err := sql.Open("sqlite3", "file::restoredb:?mode=memory&cache=shared")
	if err != nil {
		return fmt.Errorf("open in-memory db: %w", err)
	}
	defer restore.Close()
	// Execute the snapshot.
	restoreConn, err := restore.Conn(ctx)
	if err != nil {
		return fmt.Errorf("get db connection: %w", err)
	}
	var rawConn *sqlite3.SQLiteConn
	err = restoreConn.Raw(func(driverConn interface{}) error {
		rawConn = driverConn.(*sqlite3.SQLiteConn)
		return rawConn.Deserialize(data, schema)
	})
	if err != nil {
		return fmt.Errorf("deserialize db: %w", err)
	}
	// Drop all tables.
	writeConn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("get db connection: %w", err)
	}
	_, err = writeConn.ExecContext(ctx, `PRAGMA writable_schema = 1; 
	DELETE FROM sqlite_master WHERE type IN ('table', 'index', 'trigger', 'view'); 
	PRAGMA writable_schema = 0;`)
	if err != nil {
		return fmt.Errorf("drop tables: %w", err)
	}
	// Vacuum and integrity check.
	_, err = writeConn.ExecContext(ctx, "VACUUM; PRAGMA INTEGRITY_CHECK;")
	if err != nil {
		return fmt.Errorf("vacuum and integrity check: %w", err)
	}
	// Restore the deserialized database.
	err = writeConn.Raw(func(driverConn interface{}) error {
		c := driverConn.(*sqlite3.SQLiteConn)
		backup, err := c.Backup(schema, rawConn, schema)
		if err != nil {
			return fmt.Errorf("restore deserialized db: %w", err)
		}
		for {
			done, err := backup.Step(-1)
			if err != nil {
				return fmt.Errorf("restore step: %w", err)
			}
			if done {
				break
			}
		}
		return backup.Finish()
	})
	if err != nil {
		return fmt.Errorf("restore db: %w", err)
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
