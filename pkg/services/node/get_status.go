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
	"context"
	"strconv"
	"time"

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/webmeshproj/webmesh/pkg/version"
)

func (s *Server) GetStatus(ctx context.Context, req *v1.GetStatusRequest) (*v1.Status, error) {
	if req.GetId() != "" && req.GetId() != string(s.store.ID()) {
		return s.getRemoteNodeStatus(ctx, req.GetId())
	}
	var leader string
	var err error
	leader, err = s.store.Leader()
	if err != nil {
		s.log.Error("failed to lookup current leader", slog.String("error", err.Error()))
	}
	stats := s.store.Raft().Raft().Stats()
	var term uint64
	if termStr, ok := stats["term"]; ok {
		term, err = strconv.ParseUint(termStr, 10, 64)
		if err != nil {
			return nil, err
		}
	}
	ifaceMetrics, err := s.store.Network().WireGuard().Metrics()
	if err != nil {
		return nil, err
	}
	return &v1.Status{
		Id:        string(s.store.ID()),
		Version:   version.Version,
		Commit:    version.Commit,
		BuildDate: version.BuildDate,
		Uptime:    time.Since(s.startedAt).String(),
		StartedAt: timestamppb.New(s.startedAt),
		Features:  s.features,
		ClusterStatus: func() v1.ClusterStatus {
			if s.store.Raft().IsLeader() {
				return v1.ClusterStatus_CLUSTER_LEADER
			}
			config := s.store.Raft().Configuration()
			for _, srv := range config.Servers {
				if string(srv.ID) == s.store.ID() {
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
		CurrentLeader:    leader,
		CurrentTerm:      term,
		LastLogIndex:     s.store.Raft().Raft().LastIndex(),
		LastApplied:      s.store.Raft().Raft().AppliedIndex(),
		InterfaceMetrics: ifaceMetrics,
	}, nil
}

func (s *Server) getRemoteNodeStatus(ctx context.Context, nodeID string) (*v1.Status, error) {
	conn, err := s.store.Dial(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return v1.NewNodeClient(conn).GetStatus(ctx, &v1.GetStatusRequest{
		Id: nodeID,
	})
}
