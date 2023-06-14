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

package meshapi

import (
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/meshdb/peers"
)

func (s *Server) GetNode(ctx context.Context, req *v1.GetNodeRequest) (*v1.MeshNode, error) {
	node, err := s.peers.Get(ctx, req.GetId())
	if err != nil {
		if err == peers.ErrNodeNotFound {
			return nil, status.Errorf(codes.NotFound, "node %s not found", req.GetId())
		}
		return nil, status.Errorf(codes.Internal, "failed to get node: %v", err)
	}
	servers := s.store.Raft().GetConfiguration().Configuration().Servers
	leader, err := s.store.Leader()
	if err != nil {
		context.LoggerFrom(ctx).Error("failed to get leader", slog.String("error", err.Error()))
	}
	return dbNodeToAPINode(&node, leader, servers), nil
}
