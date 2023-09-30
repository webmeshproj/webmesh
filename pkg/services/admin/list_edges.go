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

// Package admin provides the admin gRPC server.
package admin

import (
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/context"
)

func (s *Server) ListEdges(ctx context.Context, _ *emptypb.Empty) (*v1.MeshEdges, error) {
	edges, err := s.db.PeerGraph().Edges()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	out := make([]*v1.MeshEdge, len(edges))
	for i, edge := range edges {
		out[i] = &v1.MeshEdge{
			Source:     edge.Source.String(),
			Target:     edge.Target.String(),
			Weight:     int32(edge.Properties.Weight),
			Attributes: edge.Properties.Attributes,
		}
	}
	return &v1.MeshEdges{Items: out}, nil
}
