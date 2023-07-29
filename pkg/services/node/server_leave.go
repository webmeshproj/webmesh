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

package node

import (
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/services/leaderproxy"
)

func (s *Server) Leave(ctx context.Context, req *v1.LeaveRequest) (*emptypb.Empty, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if !s.store.Raft().IsLeader() {
		return nil, status.Errorf(codes.FailedPrecondition, "not leader")
	}
	// Check that the node is indeed who they say they are
	if !s.insecure {
		if proxiedFor, ok := leaderproxy.ProxiedFor(ctx); ok {
			if proxiedFor != req.GetId() {
				return nil, status.Errorf(codes.PermissionDenied, "proxied for %s, not %s", proxiedFor, req.GetId())
			}
		} else {
			if peer, ok := context.AuthenticatedCallerFrom(ctx); ok {
				if peer != req.GetId() {
					return nil, status.Errorf(codes.PermissionDenied, "peer id %s, not %s", peer, req.GetId())
				}
			} else {
				return nil, status.Error(codes.PermissionDenied, "no peer authentication info in context")
			}
		}
	}
	s.log.Info("removing raft server", "id", req.GetId())
	err := s.store.Raft().RemoveServer(ctx, req.GetId(), false)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to remove voter: %v", err)
	}
	err = s.peers.Delete(ctx, req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete peer: %v", err)
	}
	return &emptypb.Empty{}, nil
}
