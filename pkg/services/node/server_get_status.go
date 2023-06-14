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
	"errors"
	"strconv"
	"time"

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/webmeshproj/node/pkg/meshdb/state"
	"github.com/webmeshproj/node/pkg/version"
)

func (s *Server) GetStatus(ctx context.Context, req *v1.GetStatusRequest) (*v1.Status, error) {
	if req.GetId() != "" && req.GetId() != string(s.store.ID()) {
		return s.getRemoteNodeStatus(ctx, req.GetId())
	}
	var leader raft.ServerID
	var err error
	leader, err = s.store.Leader()
	if err != nil {
		s.log.Error("failed to lookup current leader", slog.String("error", err.Error()))
	}
	stats := s.store.Raft().Stats()
	var term uint64
	if termStr, ok := stats["term"]; ok {
		term, err = strconv.ParseUint(termStr, 10, 64)
		if err != nil {
			return nil, err
		}
	}
	ifaceMetrics, err := s.store.Wireguard().Metrics()
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
			if s.store.IsLeader() {
				return v1.ClusterStatus_CLUSTER_LEADER
			}
			config := s.store.Raft().GetConfiguration().Configuration()
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
		CurrentLeader:    string(leader),
		CurrentTerm:      term,
		LastLogIndex:     s.store.Raft().LastIndex(),
		LastApplied:      s.store.Raft().AppliedIndex(),
		InterfaceMetrics: ifaceMetrics,
	}, nil
}

func (s *Server) getRemoteNodeStatus(ctx context.Context, nodeID string) (*v1.Status, error) {
	addr, err := s.meshstate.GetNodePrivateRPCAddress(ctx, nodeID)
	if err != nil {
		if errors.Is(err, state.ErrNodeNotFound) {
			return nil, status.Errorf(codes.NotFound, "node %s not found", nodeID)
		}
		return nil, status.Errorf(codes.FailedPrecondition, "could not find rpc address for node %s: %s", nodeID, err.Error())
	}
	var creds credentials.TransportCredentials
	if s.tlsConfig == nil {
		creds = insecure.NewCredentials()
	} else {
		creds = credentials.NewTLS(s.tlsConfig)
	}
	s.log.Info("dialing node for status", slog.String("node", nodeID), slog.String("addr", addr.String()))
	conn, err := grpc.DialContext(ctx, addr.String(), grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "could not connect to node %s: %s", nodeID, err.Error())
	}
	defer conn.Close()
	return v1.NewNodeClient(conn).GetStatus(ctx, &v1.GetStatusRequest{
		Id: nodeID,
	})
}
