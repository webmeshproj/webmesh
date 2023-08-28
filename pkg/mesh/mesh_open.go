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

package mesh

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/net"
	"github.com/webmeshproj/webmesh/pkg/plugins"
	"github.com/webmeshproj/webmesh/pkg/raft"
)

// Open opens the store.
func (s *meshStore) Open(ctx context.Context, opts ConnectOptions) (err error) {
	if s.open.Load() {
		return ErrOpen
	}
	log := s.log
	// If bootstrap and force are set, clear the data directory.
	if s.opts.Bootstrap.Enabled && s.opts.Bootstrap.Force {
		log.Warn("force bootstrap enabled, clearing data directory")
		err = os.RemoveAll(s.opts.Raft.DataDir)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove all %q: %w", s.opts.Raft.DataDir, err)
		}
	}
	// Create the plugin manager
	s.plugins, err = plugins.NewManager(ctx, s.opts.Plugins)
	if err != nil {
		return fmt.Errorf("failed to load plugins: %w", err)
	}
	// Create the raft node
	s.opts.Raft.OnObservation = s.newObserver()
	s.opts.Raft.OnSnapshotRestore = func(ctx context.Context, meta *raft.SnapshotMeta, data io.ReadCloser) {
		// Dispatch the snapshot to any storage plugins.
		if err = s.plugins.ApplySnapshot(ctx, meta, data); err != nil {
			// This is non-fatal for now.
			s.log.Error("failed to apply snapshot to plugins", slog.String("error", err.Error()))
		}
	}
	s.opts.Raft.OnApplyLog = func(ctx context.Context, term, index uint64, log *v1.RaftLogEntry) {
		// Dispatch the log entry to any storage plugins.
		if _, err := s.plugins.ApplyRaftLog(ctx, &v1.StoreLogRequest{
			Term:  term,
			Index: index,
			Log:   log,
		}); err != nil {
			// This is non-fatal for now.
			s.log.Error("failed to apply log to plugins", slog.String("error", err.Error()))
		}
	}
	if s.opts.IsRaftMember() {
		s.raft = raft.New(s.opts.Raft)
	} else {
		s.raft = raft.NewPassthrough(s)
	}
	startOpts := raft.StartOptions{
		NodeID:      s.ID(),
		Transport:   opts.RaftTransport,
		MeshStorage: opts.MeshStorage,
		RaftStorage: opts.RaftStorage,
	}
	err = s.raft.Start(ctx, &startOpts)
	if err != nil {
		return fmt.Errorf("start raft: %w", err)
	}
	// Start serving storage queries for plugins.
	go s.plugins.ServeStorage(s.raft.Storage())
	handleErr := func(cause error) error {
		s.kvSubCancel()
		log.Error("failed to open store", slog.String("error", err.Error()))
		perr := s.plugins.Close()
		if perr != nil {
			log.Error("failed to close plugin manager", slog.String("error", perr.Error()))
		}
		cerr := s.raft.Stop(ctx)
		if cerr != nil {
			log.Error("failed to stop raft node", slog.String("error", cerr.Error()))
		}
		return cause
	}
	// Create the network manager
	s.nw = net.New(s.Storage(), &net.Options{
		NodeID:                s.ID(),
		InterfaceName:         s.opts.WireGuard.InterfaceName,
		ForceReplace:          s.opts.WireGuard.ForceInterfaceName,
		ListenPort:            s.opts.WireGuard.ListenPort,
		PersistentKeepAlive:   s.opts.WireGuard.PersistentKeepAlive,
		ForceTUN:              s.opts.WireGuard.ForceTUN,
		Modprobe:              s.opts.WireGuard.Modprobe,
		MTU:                   s.opts.WireGuard.MTU,
		RecordMetrics:         s.opts.WireGuard.RecordMetrics,
		RecordMetricsInterval: s.opts.WireGuard.RecordMetricsInterval,
		RaftPort:              int(s.raft.ListenPort()),
		GRPCPort:              s.opts.Mesh.GRPCAdvertisePort,
		ZoneAwarenessID:       s.opts.Mesh.ZoneAwarenessID,
		DialOptions:           s.Credentials(context.Background()),
		DisableIPv4:           s.opts.Mesh.NoIPv4,
		DisableIPv6:           s.opts.Mesh.NoIPv6,
	})
	// At this point we are open for business.
	s.open.Store(true)
	key, err := s.loadWireGuardKey(ctx)
	if err != nil {
		return fmt.Errorf("load wireguard key: %w", err)
	}
	if s.opts.Bootstrap.Enabled {
		// Attempt bootstrap.
		log.Info("bootstrapping cluster")
		if err = s.bootstrap(ctx, opts.JoinRoundTripper, opts.Features, key); err != nil {
			return handleErr(fmt.Errorf("bootstrap: %w", err))
		}
	} else if opts.JoinRoundTripper != nil {
		// Attempt to join the cluster.
		err = s.join(ctx, opts.JoinRoundTripper, opts.Features, key)
		if err != nil {
			return handleErr(fmt.Errorf("join: %w", err))
		}
	} else {
		// We neither had the bootstrap flag nor any join flags set.
		// This means we are possibly a single node cluster.
		// Recover our previous wireguard configuration and start up.
		if err := s.recoverWireguard(ctx); err != nil {
			return fmt.Errorf("recover wireguard: %w", err)
		}
	}
	// Register an update hook to watch for network changes.
	s.kvSubCancel, err = s.raft.Storage().Subscribe(context.Background(), "", s.onDBUpdate)
	if err != nil {
		return handleErr(fmt.Errorf("subscribe: %w", err))
	}
	if s.opts.Discovery != nil && s.opts.Discovery.Announce {
		err = s.AnnounceDHT(ctx, s.opts.Discovery)
		if err != nil {
			return handleErr(fmt.Errorf("announce dht: %w", err))
		}
	}
	return nil
}
