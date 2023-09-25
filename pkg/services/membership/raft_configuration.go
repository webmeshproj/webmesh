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

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
)

func (s *Server) GetRaftConfiguration(ctx context.Context, _ *v1.RaftConfigurationRequest) (*v1.RaftConfigurationResponse, error) {
	if !context.IsInNetwork(ctx, s.wg) {
		addr, _ := context.PeerAddrFrom(ctx)
		s.log.Warn("Received GetRaftConfiguration request from out of network", slog.String("peer", addr.String()))
		return nil, status.Errorf(codes.PermissionDenied, "request is not in-network")
	}
	leader, err := s.raft.LeaderID()
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "no leader: %v", err)
	}
	config, err := s.raft.Configuration()
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "failed to get configuration: %v", err)
	}
	resp := &v1.RaftConfigurationResponse{
		Servers: make([]*v1.RaftServer, len(config.Servers)),
	}
	for _, srv := range config.Servers {
		resp.Servers = append(resp.Servers, &v1.RaftServer{
			Id:      string(srv.ID),
			Address: string(srv.Address),
			Suffrage: func() v1.ClusterStatus {
				if string(srv.ID) == leader {
					return v1.ClusterStatus_CLUSTER_LEADER
				}
				switch srv.Suffrage {
				case raft.Voter:
					return v1.ClusterStatus_CLUSTER_VOTER
				case raft.Nonvoter:
					return v1.ClusterStatus_CLUSTER_OBSERVER
				default:
					return v1.ClusterStatus_CLUSTER_STATUS_UNKNOWN
				}
			}(),
		})
	}
	return resp, nil
}
