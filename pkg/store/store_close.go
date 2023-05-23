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

	"golang.org/x/exp/slog"
)

// Close closes the store.
func (s *store) Close(ctx context.Context) error {
	if !s.open.Load() {
		return ErrNotOpen
	}
	defer s.open.Store(false)
	if s.fw != nil {
		// Clear the firewall rules last to not mess with the
		// wireguard interface.
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
		if s.observerClose != nil {
			close(s.observerClose)
			select {
			case <-ctx.Done():
				// Fallthrough anyway
			case <-s.observerDone:
			}
		}
		if err := s.Stepdown(true); err != nil && err != ErrNotLeader {
			return fmt.Errorf("stepdown: %w", err)
		}
		if err := s.raft.Shutdown().Error(); err != nil {
			return fmt.Errorf("raft shutdown: %w", err)
		}
	}
	if s.raftTransport != nil {
		if err := s.raftTransport.Close(); err != nil {
			return fmt.Errorf("raft transport close: %w", err)
		}
	}
	if s.data != nil {
		if err := s.data.Close(); err != nil {
			return fmt.Errorf("data close: %w", err)
		}
	}
	if s.logDB != nil {
		if err := s.logDB.Close(); err != nil {
			return fmt.Errorf("log db close: %w", err)
		}
	}
	if s.stableDB != nil {
		if err := s.stableDB.Close(); err != nil {
			return fmt.Errorf("stable db close: %w", err)
		}
	}
	return nil
}
