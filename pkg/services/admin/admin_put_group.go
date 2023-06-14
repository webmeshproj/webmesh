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
	"context"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/node/pkg/services/rbac"
)

var putGroupAction = rbac.Actions{
	{
		Resource: v1.RuleResource_RESOURCE_GROUPS,
		Verb:     v1.RuleVerbs_VERB_PUT,
	},
}

func (s *Server) PutGroup(ctx context.Context, group *v1.Group) (*emptypb.Empty, error) {
	if !s.store.IsLeader() {
		return nil, status.Error(codes.Unavailable, "not the leader")
	}
	if group.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "group name is required")
	}
	if ok, err := s.rbacEval.Evaluate(ctx, putGroupAction.For(group.GetName())); !ok {
		return nil, status.Error(codes.PermissionDenied, "caller does not have permission to put groups")
	} else if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if len(group.GetSubjects()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "group must have at least one node or user")
	}
	err := s.rbac.PutGroup(ctx, group)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &emptypb.Empty{}, nil
}
