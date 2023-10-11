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
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

func (s *Server) GetStatus(ctx context.Context, req *v1.GetStatusRequest) (*v1.Status, error) {
	if req.GetId() != "" && req.GetId() != s.NodeID.String() {
		return s.getRemoteNodeStatus(ctx, types.NodeID(req.GetId()))
	}
	ifaceMetrics, err := s.Meshnet.WireGuard().Metrics()
	if err != nil {
		return nil, err
	}
	storageStatus := s.Storage.Status()
	var leaderID string
	var ourStatus v1.ClusterStatus
	for _, node := range storageStatus.GetPeers() {
		if node.GetId() == s.NodeID.String() {
			ourStatus = node.GetClusterStatus()
		}
		if node.GetClusterStatus() == v1.ClusterStatus_CLUSTER_LEADER {
			leaderID = node.GetId()
		}
	}
	return &v1.Status{
		Id:               s.NodeID.String(),
		Description:      s.Description,
		Version:          s.Version.Version,
		Commit:           s.Version.Commit,
		BuildDate:        s.Version.BuildDate,
		Uptime:           time.Since(s.startedAt).String(),
		StartedAt:        timestamppb.New(s.startedAt),
		Features:         s.Features,
		ClusterStatus:    ourStatus,
		CurrentLeader:    leaderID,
		InterfaceMetrics: ifaceMetrics,
	}, nil
}

func (s *Server) getRemoteNodeStatus(ctx context.Context, nodeID types.NodeID) (*v1.Status, error) {
	conn, err := s.NodeDialer.DialNode(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return v1.NewNodeClient(conn).GetStatus(ctx, &v1.GetStatusRequest{
		Id: nodeID.String(),
	})
}
