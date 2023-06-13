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
	"context"
	"database/sql"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/hashicorp/raft"
	boltdb "github.com/hashicorp/raft-boltdb"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/node/pkg/meshdb/models"
	"github.com/webmeshproj/node/pkg/meshdb/snapshots"
)

// Open opens the store.
func (s *store) Open() error {
	if s.open.Load() {
		return ErrOpen
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.opts.Raft.StartupTimeout)
	defer cancel()
	log := s.log
	handleErr := func(err error) error {
		if s.raftTransport != nil {
			defer s.raftTransport.Close()
		}
		if s.raft != nil {
			if shutdownErr := s.raft.Shutdown().Error(); shutdownErr != nil {
				err = fmt.Errorf("%w: %v", err, shutdownErr)
			}
		}
		if s.logDB != nil {
			if closeErr := s.logDB.Close(); closeErr != nil {
				err = fmt.Errorf("%w: %v", err, closeErr)
			}
		}
		if s.stableDB != nil {
			if closeErr := s.stableDB.Close(); closeErr != nil {
				err = fmt.Errorf("%w: %v", err, closeErr)
			}
		}
		return err
	}
	var err error
	// Register a raft db driver.
	raftDriverName := uuid.NewString()
	sql.Register(raftDriverName, &raftDBDriver{s})
	// If bootstrap and force are set, clear the data directory.
	if s.opts.Bootstrap.Enabled && s.opts.Bootstrap.Force {
		err = os.RemoveAll(s.opts.Raft.DataDir)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove all %q: %w", s.opts.Raft.DataDir, err)
		}
	}
	// Ensure the data and snapshots directory exists.
	if !s.opts.Raft.InMemory {
		err = os.MkdirAll(s.opts.Raft.DataDir, 0755)
		if err != nil {
			return fmt.Errorf("mkdir %q: %w", s.opts.Raft.DataDir, err)
		}
		log = log.With(slog.String("data-dir", s.opts.Raft.DataDir))
	} else {
		log = log.With(slog.String("data-dir", ":memory:"))
	}
	// Create the raft network transport
	log.Debug("creating raft network transport")
	s.raftTransport = raft.NewNetworkTransport(s.sl,
		s.opts.Raft.ConnectionPoolCount,
		s.opts.Raft.ConnectionTimeout,
		&logWriter{log: s.log},
	)
	// Create the raft stores.
	log.Debug("creating boltdb stores")
	if s.opts.Raft.InMemory {
		s.logDB = newInmemStore()
		s.stableDB = newInmemStore()
		s.raftSnapshots = raft.NewInmemSnapshotStore()
	} else {
		s.logDB, err = boltdb.NewBoltStore(s.opts.Raft.LogFilePath())
		if err != nil {
			return handleErr(fmt.Errorf("new bolt store %q: %w", s.opts.Raft.LogFilePath(), err))
		}
		s.stableDB, err = boltdb.NewBoltStore(s.opts.Raft.StableStoreFilePath())
		if err != nil {
			return handleErr(fmt.Errorf("new bolt store %q: %w", s.opts.Raft.StableStoreFilePath(), err))
		}
		s.raftSnapshots, err = raft.NewFileSnapshotStoreWithLogger(
			s.opts.Raft.DataDir,
			int(s.opts.Raft.SnapshotRetention),
			s.opts.Raft.Logger("snapshots"),
		)
		if err != nil {
			return handleErr(fmt.Errorf("new file snapshot store %q: %w", s.opts.Raft.DataDir, err))
		}
	}
	// Create the data stores.
	log.Debug("creating data store")
	dataPath := "file:raftdata?mode=memory&cache=shared&_foreign_keys=on&_case_sensitive_like=on&synchronous=full"
	s.weakData, err = sql.Open("sqlite3", dataPath)
	if err != nil {
		return handleErr(fmt.Errorf("open data sqlite: %w", err))
	}
	s.raftData, err = sql.Open(raftDriverName, "")
	if err != nil {
		return handleErr(fmt.Errorf("open raft sqlite: %w", err))
	}
	s.snapshotter = snapshots.New(s.weakData)

	// Check if we have a snapshot to restore from.
	log.Debug("checking for snapshot")
	snapshots, err := s.raftSnapshots.List()
	if err != nil {
		return handleErr(fmt.Errorf("list snapshots: %w", err))
	}
	if len(snapshots) > 0 {
		latest := snapshots[0]
		log.Info("restoring from snapshot",
			slog.String("id", latest.ID),
			slog.Int("term", int(latest.Term)),
			slog.Int("index", int(latest.Index)))
		_, reader, err := s.raftSnapshots.Open(latest.ID)
		if err != nil {
			return handleErr(fmt.Errorf("open snapshot: %w", err))
		}
		if err = s.snapshotter.Restore(ctx, reader); err != nil {
			return handleErr(fmt.Errorf("restore snapshot: %w", err))
		}
		s.currentTerm.Store(latest.Term)
		s.lastAppliedIndex.Store(latest.Index)
	}

	// Create the raft instance.
	log.Info("starting raft instance",
		slog.String("listen-addr", string(s.raftTransport.LocalAddr())),
	)
	s.raft, err = raft.NewRaft(
		s.opts.Raft.RaftConfig(s.ID()),
		s,
		&monotonicLogStore{s.logDB},
		s.stableDB,
		s.raftSnapshots,
		s.raftTransport)
	if err != nil {
		return handleErr(fmt.Errorf("new raft: %w", err))
	}
	// Bootstrap the cluster if needed.
	if s.opts.Bootstrap.Enabled {
		// Database gets migrated during bootstrap.
		log.Info("bootstrapping cluster")
		if err = s.bootstrap(ctx); err != nil {
			return handleErr(fmt.Errorf("bootstrap: %w", err))
		}
	} else if s.opts.Mesh.JoinAddress != "" || len(s.opts.Mesh.PeerDiscoveryAddresses) > 0 {
		log.Debug("migrating raft database")
		if err = models.MigrateRaftDB(s.weakData); err != nil {
			return fmt.Errorf("raft db migrate: %w", err)
		}
		ctx, cancel := context.WithTimeout(ctx, s.opts.Mesh.JoinTimeout)
		defer cancel()
		if len(s.opts.Mesh.PeerDiscoveryAddresses) > 0 {
			err = s.joinWithPeerDiscovery(ctx)
		} else {
			err = s.join(ctx, s.opts.Mesh.JoinAddress, s.opts.Mesh.MaxJoinRetries)
		}
		if err != nil {
			return handleErr(fmt.Errorf("join: %w", err))
		}
	} else {
		// We neither had the bootstrap flag nor the join flag set.
		// This means we are possibly a single node cluster.
		// Recover our previous wireguard configuration and start up.
		log.Debug("migrating raft database")
		if err = models.MigrateRaftDB(s.weakData); err != nil {
			return fmt.Errorf("raft db migrate: %w", err)
		}
		if err := s.recoverWireguard(ctx); err != nil {
			return fmt.Errorf("recover wireguard: %w", err)
		}
	}
	// Register observers.
	s.observerChan = make(chan raft.Observation, s.opts.Raft.ObserverChanBuffer)
	s.observer = raft.NewObserver(s.observerChan, false, func(o *raft.Observation) bool {
		return true
	})
	s.raft.RegisterObserver(s.observer)
	s.observerClose, s.observerDone = s.observe()
	s.open.Store(true)
	return nil
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
