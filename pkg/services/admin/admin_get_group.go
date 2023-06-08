/*
Copyright 2023.

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

	rbacdb "github.com/webmeshproj/node/pkg/meshdb/rbac"
	"github.com/webmeshproj/node/pkg/services/rbac"
)

var getGroupAction = &rbac.Action{
	Resource: v1.RuleResource_RESOURCE_GROUPS,
	Verb:     v1.RuleVerbs_VERB_GET,
}

func (s *Server) GetGroup(ctx context.Context, group *v1.Group) (*v1.Group, error) {
	if group.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "group name is required")
	}
	if ok, err := s.rbacEval.Evaluate(ctx, getGroupAction.For(group.GetName())); !ok {
		return nil, status.Error(codes.PermissionDenied, "caller does not have permission to get groups")
	} else if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	group, err := s.rbac.GetGroup(ctx, group.GetName())
	if err != nil {
		if err == rbacdb.ErrGroupNotFound {
			return nil, status.Errorf(codes.NotFound, "group %q not found", group.GetName())
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return group, nil
}
