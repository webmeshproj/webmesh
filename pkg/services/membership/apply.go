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
	"net"
	"strings"
	"time"

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
)

func (s *Server) Apply(ctx context.Context, log *v1.RaftLogEntry) (*v1.RaftApplyResponse, error) {
	if !s.store.Raft().IsLeader() {
		return nil, status.Errorf(codes.FailedPrecondition, "not leader")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "no peer")
	}
	cfg := s.store.Raft().Configuration()
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
	// Issue a barrier to the raft cluster to ensure all nodes are
	// fully caught up before we make changes
	// TODO: Make timeout configurable
	_, err := s.store.Raft().Barrier(ctx, time.Second*15)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to send barrier: %v", err)
	}
	// Send another barrier after we're done to ensure all nodes are
	// fully caught up before we return
	defer func() {
		_, _ = s.store.Raft().Barrier(ctx, time.Second*15)
	}()
	return s.store.Raft().Apply(ctx, log)
}
