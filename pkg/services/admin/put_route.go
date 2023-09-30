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
	"github.com/webmeshproj/webmesh/pkg/services/rbac"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

var putRouteAction = rbac.Actions{
	{
		Resource: v1.RuleResource_RESOURCE_ROUTES,
		Verb:     v1.RuleVerb_VERB_PUT,
	},
}

func (s *Server) PutRoute(ctx context.Context, route *v1.Route) (*emptypb.Empty, error) {
	if !s.storage.Consensus().IsLeader() {
		return nil, status.Error(codes.FailedPrecondition, "not the leader")
	}
	rt := types.Route{Route: route}
	err := types.ValidateRoute(rt)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if ok, err := s.rbacEval.Evaluate(ctx, putRouteAction.For(route.GetName())); !ok {
		if err != nil {
			context.LoggerFrom(ctx).Error("failed to evaluate put route action", "error", err)
		}
		return nil, status.Error(codes.PermissionDenied, "caller does not have permission to put network routes")
	}
	err = s.db.Networking().PutRoute(ctx, rt)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &emptypb.Empty{}, nil
}
