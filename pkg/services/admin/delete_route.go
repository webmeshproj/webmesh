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
	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/services/rbac"
)

var deleteRouteAction = rbac.Actions{
	{
		Resource: v1.RuleResource_RESOURCE_ROUTES,
		Verb:     v1.RuleVerb_VERB_DELETE,
	},
}

func (s *Server) DeleteRoute(ctx context.Context, route *v1.Route) (*emptypb.Empty, error) {
	if !s.storage.Consensus().IsLeader() {
		return nil, status.Error(codes.FailedPrecondition, "not the leader")
	}
	if route.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "route name is required")
	}
	if ok, err := s.rbacEval.Evaluate(ctx, deleteRouteAction.For(route.GetName())); !ok {
		if err != nil {
			context.LoggerFrom(ctx).Error("failed to evaluate delete route action", "error", err)
		}
		return nil, status.Error(codes.PermissionDenied, "caller does not have permission to delete network routes")
	}
	err := s.db.Networking().DeleteRoute(ctx, route.GetName())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &emptypb.Empty{}, nil
}
