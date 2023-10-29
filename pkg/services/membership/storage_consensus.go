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

	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
)

func (s *Server) GetCurrentConsensus(ctx context.Context, _ *v1.StorageConsensusRequest) (*v1.StorageConsensusResponse, error) {
	if !context.IsInNetwork(ctx, s.meshnet) {
		addr, _ := context.PeerAddrFrom(ctx)
		s.log.Warn("Received GetStorageConfiguration request from out of network", slog.String("peer", addr.String()))
		return nil, status.Errorf(codes.PermissionDenied, "request is not in-network")
	}
	storageStatus := s.storage.Status()
	s.log.Debug("Handling GetStorageConfiguration request", slog.Any("current-status", storageStatus))
	resp := &v1.StorageConsensusResponse{
		Servers: make([]*v1.StorageServer, 0),
	}
	for _, srv := range storageStatus.GetPeers() {
		resp.Servers = append(resp.Servers, &v1.StorageServer{
			Id:        srv.GetId(),
			PublicKey: srv.GetPublicKey(),
			Address:   srv.GetAddress(),
			Suffrage:  srv.GetClusterStatus(),
		})
	}
	return resp, nil
}
