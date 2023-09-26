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
	dbutil "github.com/webmeshproj/webmesh/pkg/meshdb/util"
	"github.com/webmeshproj/webmesh/pkg/services/rbac"
)

var putEdgeAction = rbac.Actions{
	{
		Resource: v1.RuleResource_RESOURCE_EDGES,
		Verb:     v1.RuleVerb_VERB_PUT,
	},
}

func (s *Server) PutEdge(ctx context.Context, edge *v1.MeshEdge) (*emptypb.Empty, error) {
	if !s.storage.Consensus().IsLeader() {
		return nil, status.Error(codes.FailedPrecondition, "not the leader")
	}
	if edge.GetSource() == "" {
		return nil, status.Error(codes.InvalidArgument, "source cannot be empty")
	}
	if edge.GetTarget() == "" {
		return nil, status.Error(codes.InvalidArgument, "target cannot be empty")
	}
	for _, id := range []string{edge.GetSource(), edge.GetTarget()} {
		if ok, err := s.rbacEval.Evaluate(ctx, putEdgeAction.For(id)); !ok {
			if err != nil {
				context.LoggerFrom(ctx).Error("failed to evaluate put edge action", "error", err)
			}
			return nil, status.Error(codes.PermissionDenied, "caller does not have permission to put the given edge")
		}
		if !dbutil.IsValidNodeID(id) {
			return nil, status.Errorf(codes.InvalidArgument, "invalid node ID: %s", id)
		}
	}
	err := s.peers.PutEdge(ctx, edge)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &emptypb.Empty{}, nil
}
