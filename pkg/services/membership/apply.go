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

package membership

import (
	"log/slog"
	"net"
	"strings"

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage/providers/raftstorage"
)

func (s *Server) Apply(ctx context.Context, log *v1.RaftLogEntry) (*v1.RaftApplyResponse, error) {
	// Make sure the request is coming from in-network
	if !context.IsInNetwork(ctx, s.wg) {
		addr, _ := context.PeerAddrFrom(ctx)
		s.log.Warn("Received Apply request from out of network", slog.String("peer", addr.String()))
		return nil, status.Errorf(codes.PermissionDenied, "request is not in-network")
	}
	provider, ok := s.storage.(*raftstorage.Provider)
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "storage provider is not a raftstorage provider")
	}
	if !provider.Consensus().IsLeader() {
		return nil, status.Errorf(codes.FailedPrecondition, "not leader")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "no peer")
	}
	cfg, err := provider.GetRaftConfiguration()
	if err != nil {
		// Should never happen
		return nil, status.Errorf(codes.Internal, "failed to get configuration: %v", err)
	}
	var found bool
	for _, server := range cfg.Servers {
		host, _, err := net.SplitHostPort(peer.Addr.String())
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "invalid peer address")
		}
		if strings.HasPrefix(string(server.Address), host) {
			if server.Suffrage != raft.Voter {
				return nil, status.Errorf(codes.FailedPrecondition, "peer is not a voter")
			}
			found = true
			break
		}
	}
	if !found {
		return nil, status.Errorf(codes.FailedPrecondition, "peer not found in configuration")
	}
	return provider.ApplyRaftLog(ctx, log)
}
