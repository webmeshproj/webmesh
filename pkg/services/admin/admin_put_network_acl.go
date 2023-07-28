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
	"net/netip"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb/networking"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	"github.com/webmeshproj/webmesh/pkg/services/rbac"
)

var putNetworkACLAction = rbac.Actions{
	{
		Resource: v1.RuleResource_RESOURCE_NETWORK_ACLS,
		Verb:     v1.RuleVerb_VERB_PUT,
	},
}

func (s *Server) PutNetworkACL(ctx context.Context, acl *v1.NetworkACL) (*emptypb.Empty, error) {
	if !s.store.Raft().IsLeader() {
		return nil, status.Error(codes.FailedPrecondition, "not the leader")
	}
	if acl.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "acl name is required")
	}
	if ok, err := s.rbacEval.Evaluate(ctx, putNetworkACLAction.For(acl.GetName())); !ok {
		if err != nil {
			context.LoggerFrom(ctx).Error("failed to evaluate put network acl action", "error", err)
		}
		return nil, status.Error(codes.PermissionDenied, "caller does not have permission to put network acls")
	}
	if networking.IsSystemNetworkACL(acl.GetName()) {
		return nil, status.Error(codes.InvalidArgument, "cannot update system network acls")
	}
	if _, ok := v1.ACLAction_name[int32(acl.GetAction())]; !ok {
		return nil, status.Error(codes.InvalidArgument, "invalid acl action")
	}
	if allEmpty([][]string{acl.GetDestinationCidrs(), acl.GetSourceCidrs(), acl.GetSourceNodes(), acl.GetDestinationNodes()}) {
		return nil, status.Error(codes.InvalidArgument, "at least one of destination_cidrs, source_cidrs, source_nodes, or destination_nodes must be set")
	}
	if len(acl.GetSourceCidrs()) > 0 || len(acl.GetDestinationCidrs()) > 0 {
		cidrs := append(acl.GetSourceCidrs(), acl.GetDestinationCidrs()...)
		for _, cidr := range cidrs {
			_, err := netip.ParsePrefix(cidr)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid cidr: %s", cidr)
			}
		}
	}
	if len(acl.GetSourceNodes()) > 0 || len(acl.GetDestinationNodes()) > 0 {
		nodes := append(acl.GetSourceNodes(), acl.GetDestinationNodes()...)
		for _, node := range nodes {
			if !peers.IsValidID(node) {
				return nil, status.Errorf(codes.InvalidArgument, "invalid node id: %s", node)
			}
		}
	}
	err := s.networking.PutNetworkACL(ctx, acl)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &emptypb.Empty{}, nil
}

func allEmpty(ss [][]string) bool {
	for _, s := range ss {
		if len(s) != 0 {
			return false
		}
	}
	return true
}
