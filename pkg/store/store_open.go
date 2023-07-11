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
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"github.com/hashicorp/raft"
	boltdb "github.com/hashicorp/raft-boltdb"
	"github.com/mattn/go-sqlite3"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/node/pkg/meshdb/models"
	"github.com/webmeshproj/node/pkg/meshdb/snapshots"
	"github.com/webmeshproj/node/pkg/net"
	"github.com/webmeshproj/node/pkg/plugins"
)

// Open opens the store.
func (s *store) Open(ctx context.Context) error {
	if s.open.Load() {
		return ErrOpen
	}
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
	// Create the plugin manager
	s.plugins, err = plugins.New(ctx, s.opts.Plugins)
	if err != nil {
		return fmt.Errorf("failed to load plugins: %w", err)
	}
	// Create the network manager
	s.nw = net.New(s, &net.Options{
		InterfaceName:         s.opts.WireGuard.InterfaceName,
		ForceReplace:          s.opts.WireGuard.ForceInterfaceName,
		ListenPort:            s.opts.WireGuard.ListenPort,
		PersistentKeepAlive:   s.opts.WireGuard.PersistentKeepAlive,
		ForceTUN:              s.opts.WireGuard.ForceTUN,
		Modprobe:              s.opts.WireGuard.Modprobe,
		MTU:                   s.opts.WireGuard.MTU,
		RecordMetrics:         s.opts.WireGuard.RecordMetrics,
		RecordMetricsInterval: s.opts.WireGuard.RecordMetricsInterval,
		RaftPort:              s.sl.ListenPort(),
		GRPCPort:              s.opts.Mesh.GRPCPort,
		ZoneAwarenessID:       s.opts.Mesh.ZoneAwarenessID,
		DialOptions:           s.grpcCreds(ctx),
	})
	// If bootstrap and force are set, clear the data directory.
	if s.opts.Bootstrap.Enabled && s.opts.Bootstrap.Force {
		log.Warn("force bootstrap enabled, clearing data directory")
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
	raftDriverName := uuid.NewString()
	sql.Register(raftDriverName, &raftDBDriver{s})
	// Giving the db a unique name is useful for testing.
	dataPath := fmt.Sprintf("file:%s?mode=memory&cache=shared&_foreign_keys=on&_case_sensitive_like=on&synchronous=full", raftDriverName)
	s.weakData, err = sql.Open("sqlite3", dataPath)
	if err != nil {
		return handleErr(fmt.Errorf("open data sqlite: %w", err))
	}
	s.raftData, err = sql.Open(raftDriverName, "")
	if err != nil {
		return handleErr(fmt.Errorf("open raft sqlite: %w", err))
	}
	s.snapshotter = snapshots.New(s.weakData)

	// Register an update hook to watch for node changes.
	c, err := s.weakData.Conn(ctx)
	if err != nil {
		return handleErr(fmt.Errorf("get conn: %w", err))
	}
	err = c.Raw(func(driverConn interface{}) error {
		c, ok := driverConn.(*sqlite3.SQLiteConn)
		if !ok {
			return fmt.Errorf("expected *sqlite3.SQLiteConn, got %T", driverConn)
		}
		c.RegisterUpdateHook(s.onDBUpdate)
		return nil
	})
	if err != nil {
		return handleErr(fmt.Errorf("register update hook: %w", err))
	}
	if err = c.Close(); err != nil {
		return handleErr(fmt.Errorf("close conn: %w", err))
	}

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
		meta, reader, err := s.raftSnapshots.Open(latest.ID)
		if err != nil {
			return handleErr(fmt.Errorf("open snapshot: %w", err))
		}
		defer reader.Close()
		var buf bytes.Buffer
		tee := io.TeeReader(reader, &buf)
		// Restore to the in-memory database.
		if err = s.snapshotter.Restore(ctx, io.NopCloser(tee)); err != nil {
			return handleErr(fmt.Errorf("restore snapshot: %w", err))
		}
		// Dispatch the snapshot to any storage plugins.
		if err = s.plugins.ApplySnapshot(ctx, meta, io.NopCloser(&buf)); err != nil {
			// This is non-fatal for now.
			log.Error("failed to apply snapshot to plugins", slog.String("error", err.Error()))
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
	// Register observers.
	s.observerChan = make(chan raft.Observation, s.opts.Raft.ObserverChanBuffer)
	s.observer = raft.NewObserver(s.observerChan, false, func(o *raft.Observation) bool {
		return true
	})
	s.raft.RegisterObserver(s.observer)
	s.observerClose, s.observerDone = s.observe()
	// Bootstrap the cluster if needed.
	if s.opts.Bootstrap.Enabled {
		// Database gets migrated during bootstrap.
		log.Info("bootstrapping cluster")
		if err = s.bootstrap(ctx); err != nil {
			return handleErr(fmt.Errorf("bootstrap: %w", err))
		}
	} else if s.opts.Mesh.JoinAddress != "" || len(s.opts.Mesh.PeerDiscoveryAddresses) > 0 {
		log.Debug("migrating raft database")
		if err = models.MigrateDB(s.weakData); err != nil {
			return fmt.Errorf("raft db migrate: %w", err)
		}
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
		if err = models.MigrateDB(s.weakData); err != nil {
			return fmt.Errorf("raft db migrate: %w", err)
		}
		if err := s.recoverWireguard(ctx); err != nil {
			return fmt.Errorf("recover wireguard: %w", err)
		}
	}
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
