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

package node

import (
	"context"
	"time"

	v1 "gitlab.com/webmesh/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *Server) Leave(ctx context.Context, req *v1.LeaveRequest) (*emptypb.Empty, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if !s.store.IsLeader() {
		return nil, status.Errorf(codes.FailedPrecondition, "not leader")
	}
	s.log.Info("removing voter", "id", req.GetId())
	err := s.store.RemoveServer(ctx, req.GetId(), false)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to remove voter: %v", err)
	}
	// The most important thing is that we remove the voter. We should also remove the peer from
	// the database and release leases, but we don't want this to negatively impact the caller.
	// So we do it in the background.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()
		err := s.peers.Delete(ctx, req.GetId())
		if err != nil {
			s.log.Error("failed to remove node from db", slog.String("error", err.Error()))
		}
	}()
	return &emptypb.Empty{}, nil
}
