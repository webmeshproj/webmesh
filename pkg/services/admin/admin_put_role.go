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
	rbacdb "github.com/webmeshproj/webmesh/pkg/meshdb/rbac"
	"github.com/webmeshproj/webmesh/pkg/services/rbac"
)

var putRoleAction = rbac.Actions{
	{
		Resource: v1.RuleResource_RESOURCE_ROLES,
		Verb:     v1.RuleVerb_VERB_PUT,
	},
}

func (s *Server) PutRole(ctx context.Context, role *v1.Role) (*emptypb.Empty, error) {
	if !s.store.IsLeader() {
		return nil, status.Error(codes.FailedPrecondition, "not the leader")
	}
	if role.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "role name must be specified")
	}
	if ok, err := s.rbacEval.Evaluate(ctx, putRoleAction.For(role.GetName())); !ok {
		if err != nil {
			context.LoggerFrom(ctx).Error("failed to evaluate put role action", "error", err)
		}
		return nil, status.Error(codes.PermissionDenied, "caller does not have permission to put roles")
	}
	if rbacdb.IsSystemRole(role.GetName()) {
		return nil, status.Error(codes.InvalidArgument, "cannot update system roles")
	}
	if len(role.GetRules()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "role must have at least one rule")
	}
	// Check if any rule has a wildcard and squash them down to a single wildcard rule.
	for _, rule := range role.GetRules() {
		if len(rule.GetVerbs()) == 0 {
			return nil, status.Error(codes.InvalidArgument, "rule must have at least one verb")
		}
		if len(rule.GetResources()) == 0 {
			return nil, status.Error(codes.InvalidArgument, "rule must have at least one resource")
		}
	Verbs:
		for _, verb := range rule.GetVerbs() {
			if _, ok := v1.RuleVerb_name[int32(verb)]; !ok {
				return nil, status.Errorf(codes.InvalidArgument, "invalid verb: %v", verb)
			}
			if verb == v1.RuleVerb_VERB_ALL {
				rule.Verbs = []v1.RuleVerb{v1.RuleVerb_VERB_ALL}
				break Verbs
			}
		}
	Resources:
		for _, resource := range rule.GetResources() {
			if _, ok := v1.RuleResource_name[int32(resource)]; !ok {
				return nil, status.Errorf(codes.InvalidArgument, "invalid resource: %v", resource)
			}
			if resource == v1.RuleResource_RESOURCE_ALL {
				rule.Resources = []v1.RuleResource{v1.RuleResource_RESOURCE_ALL}
				break Resources
			}
		}
	}
	err := s.rbac.PutRole(ctx, role)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &emptypb.Empty{}, nil
}
