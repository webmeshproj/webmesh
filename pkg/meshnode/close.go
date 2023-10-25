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

package meshnode

import (
	"fmt"
	"log/slog"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// Close closes the connection to mesh and all underlying components.
func (s *meshStore) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.open.Load() {
		return ErrNotOpen
	}
	ctx = context.WithLogger(ctx, s.log)
	defer s.open.Store(false)
	defer close(s.closec)
	s.kvSubCancel()
	if s.nw != nil {
		// Do this last so that we don't lose connectivity to the network
		defer func() {
			s.log.Debug("Closing network manager")
			if err := s.nw.Close(ctx); err != nil {
				s.log.Error("Error clearing firewall rules", slog.String("error", err.Error()))
			}
		}()
	}
	if s.plugins != nil {
		// Close the plugins
		s.log.Debug("Closing plugin manager")
		err := s.plugins.Close()
		if err != nil {
			s.log.Error("Error closing plugins", slog.String("error", err.Error()))
		}
	}
	if s.storage.Consensus().IsLeader() {
		// We need to relinquish leadership before closing the storage provider
		s.log.Debug("Relinquishing storage leadership")
		err := s.storage.Consensus().StepDown(ctx)
		if err != nil {
			s.log.Error("Error relinquishing storage leadership", slog.String("error", err.Error()))
		}
	}
	// Try to leave the cluster.
	err := s.leaveCluster(ctx)
	if err != nil {
		s.log.Error("Error leaving cluster", slog.String("error", err.Error()))
	}
	if s.storage != nil {
		s.log.Debug("Closing storage provider")
		err := s.storage.Close()
		if err != nil {
			s.log.Error("Error stopping storage provider", slog.String("error", err.Error()))
		}
	}
	s.log.Info("Webmesh node shut down")
	return nil
}

// leaveCluster attempts to remove this node from the cluster. The node must
// have already relinquished leadership before calling this method.
func (s *meshStore) leaveCluster(ctx context.Context) error {
	if s.leaveRTT == nil {
		return nil
	}
	_, err := s.leaveRTT.RoundTrip(ctx, &v1.LeaveRequest{
		Id: s.nodeID,
	})
	if err != nil {
		return fmt.Errorf("leave cluster: %w", err)
	}
	return nil
}
