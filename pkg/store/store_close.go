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
	"fmt"
	"io"

	"golang.org/x/exp/slog"
)

// Close closes the store.
func (s *store) Close() error {
	if !s.open.Load() {
		return ErrNotOpen
	}
	ctx := context.Background()
	if s.opts.ShutdownTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.opts.ShutdownTimeout)
		defer cancel()
	}
	defer s.open.Store(false)
	// Stop the observers
	close(s.observerClose)
	<-s.observerDone
	if s.fw != nil {
		// Clear the firewall rules after wireguard is shutdown
		defer func() {
			s.wgmux.Lock()
			defer s.wgmux.Unlock()
			if err := s.fw.Clear(ctx); err != nil {
				s.log.Error("error clearing firewall rules", slog.String("error", err.Error()))
			}
		}()
	}
	if s.wg != nil {
		// Close the wireguard interface last, as it will cause
		// raft operations to fail.
		defer func() {
			s.wgmux.Lock()
			defer s.wgmux.Unlock()
			if err := s.wg.Close(ctx); err != nil {
				s.log.Error("error closing wireguard interface", slog.String("error", err.Error()))
			}
		}()
	}
	if s.raft != nil {
		if s.IsLeader() {
			s.log.Debug("currently the leader, removing ourselves and stepping down")
			if s.opts.LeaveOnShutdown {
				if err := s.RemoveServer(ctx, string(s.nodeID), true); err != nil {
					return fmt.Errorf("remove voter: %w", err)
				}
			}
			// Try to step down again for good measure.
			if err := s.Stepdown(true); err != nil && err != ErrNotLeader {
				return fmt.Errorf("stepdown: %w", err)
			}
		} else if s.opts.LeaveOnShutdown {
			s.log.Debug("leaving cluster")
			// If we were not the leader, we need to leave
			if err := s.leaveCluster(context.Background()); err != nil {
				// Make this non-fatal, but it will piss off the leader.
				// TODO: The leader should run a separate goroutine
				// to remove servers that have left the cluster.
				s.log.Error("error leaving cluster", slog.String("error", err.Error()))
			}
		}
		// Finally, shutdown the raft node.
		s.log.Debug("shutting down raft")
		if err := s.raft.Shutdown().Error(); err != nil {
			return fmt.Errorf("raft shutdown: %w", err)
		}
	}
	s.log.Debug("all services shut down, closing databases")
	// None of these are strictly necessary, but we do them for
	// good measure.
	for name, closer := range map[string]io.Closer{
		"raft transport": s.raftTransport,
		"raft database":  s.weakData,
		"local database": s.localData,
		"raft log db":    s.logDB,
		"raft stable db": s.stableDB,
	} {
		s.log.Debug("closing " + name)
		if err := closer.Close(); err != nil {
			s.log.Error("error closing "+name, slog.String("error", err.Error()))
		}
	}
	return nil
}
