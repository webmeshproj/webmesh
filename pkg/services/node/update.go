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
	"golang.org/x/exp/slog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
)

func (s *Server) Update(ctx context.Context, req *v1.UpdateRequest) (*v1.UpdateResponse, error) {
	if !s.store.Raft().IsLeader() {
		return nil, status.Errorf(codes.FailedPrecondition, "not leader")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	log := s.log.With("op", "update", "id", req.GetId())
	ctx = context.WithLogger(ctx, log)

	log.Info("update request received", slog.Any("request", req))
	// Check if we haven't loaded the mesh domain and prefixes into memory yet
	err := s.loadMeshState(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load mesh state: %v", err)
	}
	return &v1.UpdateResponse{}, nil
}
