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

// Package snapshots provides an interface for managing raft snapshots.
package snapshots

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/hashicorp/raft"
	"golang.org/x/exp/slog"

	"gitlab.com/webmesh/node/pkg/models/raftdb"
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

type snapshotModel struct {
	State  []raftdb.MeshState `json:"state"`
	Nodes  []raftdb.Node      `json:"nodes"`
	Leases []raftdb.Lease     `json:"leases"`
}

func (s *snapshotter) Snapshot(ctx context.Context) (raft.FSMSnapshot, error) {
	s.log.Info("creating new snapshot")
	start := time.Now()
	q := raftdb.New(s.db)
	var model snapshotModel
	var err error
	model.State, err = q.DumpMeshState(ctx)
	if err != nil {
		return nil, fmt.Errorf("dump mesh state: %w", err)
	}
	model.Nodes, err = q.DumpNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("dump nodes: %w", err)
	}
	model.Leases, err = q.DumpLeases(ctx)
	if err != nil {
		return nil, fmt.Errorf("dump leases: %w", err)
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(model); err != nil {
		return nil, fmt.Errorf("encode snapshot model: %w", err)
	}
	s.log.Info("snapshot complete", slog.String("duration", time.Since(start).String()))
	return &snapshot{&buf}, nil
}

func (s *snapshotter) Restore(ctx context.Context, r io.ReadCloser) error {
	s.log.Info("restoring snapshot")
	start := time.Now()
	var model snapshotModel
	if err := json.NewDecoder(r).Decode(&model); err != nil {
		return fmt.Errorf("decode snapshot model: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	func() {
		err := tx.Rollback()
		if err != sql.ErrTxDone && err != nil {
			s.log.Error("rollback transaction", slog.String("error", err.Error()))
		}
	}()
	q := raftdb.New(tx)
	err = q.DropMeshState(ctx)
	if err != nil {
		return fmt.Errorf("drop mesh state: %w", err)
	}
	err = q.DropNodes(ctx)
	if err != nil {
		return fmt.Errorf("drop nodes: %w", err)
	}
	err = q.DropLeases(ctx)
	if err != nil {
		return fmt.Errorf("drop leases: %w", err)
	}
	for _, state := range model.State {
		s.log.Debug("restoring mesh state", slog.Any("state", state))
		// nolint:gosimple
		err = q.RestoreMeshState(ctx, raftdb.RestoreMeshStateParams{
			Key:   state.Key,
			Value: state.Value,
		})
		if err != nil {
			return fmt.Errorf("restore mesh state: %w", err)
		}
	}
	for _, node := range model.Nodes {
		s.log.Debug("restoring node", slog.Any("node", node))
		// nolint:gosimple
		err = q.RestoreNode(ctx, raftdb.RestoreNodeParams{
			ID:              node.ID,
			PublicKey:       node.PublicKey,
			RaftPort:        node.RaftPort,
			GrpcPort:        node.GrpcPort,
			WireguardPort:   node.WireguardPort,
			PrimaryEndpoint: node.PrimaryEndpoint,
			Endpoints:       node.Endpoints,
			NetworkIpv6:     node.NetworkIpv6,
			CreatedAt:       node.CreatedAt,
			UpdatedAt:       node.UpdatedAt,
		})
		if err != nil {
			return fmt.Errorf("restore node: %w", err)
		}
	}
	for _, lease := range model.Leases {
		s.log.Debug("restoring lease", slog.Any("lease", lease))
		// nolint:gosimple
		err = q.RestoreLease(ctx, raftdb.RestoreLeaseParams{
			NodeID:    lease.NodeID,
			Ipv4:      lease.Ipv4,
			CreatedAt: lease.CreatedAt,
		})
		if err != nil {
			return fmt.Errorf("restore lease: %w", err)
		}
	}
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	s.log.Info("restored snapshot", slog.String("duration", time.Since(start).String()))
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
