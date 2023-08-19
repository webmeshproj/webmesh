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
	"log/slog"
	"time"

	v1 "github.com/webmeshproj/api/v1"
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
			} else if s.store.Raft().IsVoter() {
				return v1.ClusterStatus_CLUSTER_VOTER
			} else if s.store.Raft().IsObserver() {
				return v1.ClusterStatus_CLUSTER_NON_VOTER
			}
			return v1.ClusterStatus_CLUSTER_NODE
		}(),
		CurrentLeader:    leader,
		LastLogIndex:     s.store.Raft().LastIndex(),
		LastApplied:      s.store.Raft().LastAppliedIndex(),
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
