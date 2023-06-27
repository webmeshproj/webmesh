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

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/meshdb/peers"
	rbacdb "github.com/webmeshproj/node/pkg/meshdb/rbac"
	"github.com/webmeshproj/node/pkg/services/rbac"
)

var putRoleBindingAction = rbac.Actions{
	{
		Resource: v1.RuleResource_RESOURCE_ROLE_BINDINGS,
		Verb:     v1.RuleVerb_VERB_PUT,
	},
}

func (s *Server) PutRoleBinding(ctx context.Context, rb *v1.RoleBinding) (*emptypb.Empty, error) {
	if !s.store.IsLeader() {
		return nil, status.Error(codes.FailedPrecondition, "not the leader")
	}
	if rb.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "rolebinding name cannot be empty")
	}
	if ok, err := s.rbacEval.Evaluate(ctx, putRoleBindingAction.For(rb.GetName())); !ok {
		if err != nil {
			context.LoggerFrom(ctx).Error("failed to evaluate put role binding action", "error", err)
		}
		return nil, status.Error(codes.PermissionDenied, "caller does not have permission to put rolebindings")
	}
	if rbacdb.IsSystemRoleBinding(rb.GetName()) {
		return nil, status.Error(codes.InvalidArgument, "cannot update system rolebindings")
	}
	if rb.GetRole() == "" {
		return nil, status.Error(codes.InvalidArgument, "rolebinding must have a role")
	}
	if len(rb.GetSubjects()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "rolebinding must have at least one subject")
	}
	// Squash subjects if an all subject is present
	for _, subject := range rb.GetSubjects() {
		if subject.GetName() == "*" && subject.GetType() == v1.SubjectType_SUBJECT_ALL {
			rb.Subjects = []*v1.Subject{subject}
			break
		}
		if _, ok := v1.SubjectType_name[int32(subject.GetType())]; !ok {
			return nil, status.Error(codes.InvalidArgument, "subject type must be valid")
		}
		if !peers.NodeIDIsValid(subject.GetName()) {
			return nil, status.Error(codes.InvalidArgument, "subject name must be a valid node ID")
		}
	}
	err := s.rbac.PutRoleBinding(ctx, rb)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &emptypb.Empty{}, nil
}
