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

	"github.com/hashicorp/raft"
	v1 "gitlab.com/webmesh/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gitlab.com/webmesh/node/pkg/version"
)

func (s *Server) GetStatus(ctx context.Context, req *emptypb.Empty) (*v1.Status, error) {
	var leader raft.ServerID
	var err error
	leader, err = s.store.Leader()
	if err != nil {
		s.log.Error("failed to lookup current leader", slog.String("error", err.Error()))
	}
	return &v1.Status{
		Version:   version.Version,
		Commit:    version.Commit,
		BuildDate: version.BuildDate,
		Uptime:    time.Since(s.startedAt).String(),
		StartedAt: timestamppb.New(s.startedAt),
		Features:  s.features,
		Peers:     uint32(len(s.store.Wireguard().Peers())),
		Status: func() v1.ClusterStatus {
			if s.store.IsLeader() {
				return v1.ClusterStatus_CLUSTER_LEADER
			}
			config := s.store.Raft().GetConfiguration().Configuration()
			for _, srv := range config.Servers {
				if srv.ID == s.store.ID() {
					switch srv.Suffrage {
					case raft.Voter:
						return v1.ClusterStatus_CLUSTER_VOTER
					case raft.Nonvoter:
						return v1.ClusterStatus_CLUSTER_NON_VOTER
					}
				}
			}
			return v1.ClusterStatus_CLUSTER_STATUS_UNKNOWN
		}(),
		CurrentLeader: string(leader),
	}, nil
}
