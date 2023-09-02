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

package storage

import (
	"log/slog"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb"
	"github.com/webmeshproj/webmesh/pkg/services/rbac"
)

var canPublishAction = rbac.Actions{
	{
		Verb:     v1.RuleVerb_VERB_PUT,
		Resource: v1.RuleResource_RESOURCE_PUBSUB,
	},
}

func (s *Server) Publish(ctx context.Context, req *v1.PublishRequest) (*v1.PublishResponse, error) {
	if !context.IsInNetwork(ctx, s.wg) {
		addr, _ := context.PeerAddrFrom(ctx)
		s.log.Warn("Received Publish request from out of network", slog.String("peer", addr.String()))
		return nil, status.Errorf(codes.PermissionDenied, "request is not in-network")
	}
	if !s.raft.IsVoter() && !s.raft.IsObserver() {
		// In theory - non-raft members shouldn't even expose the Node service.
		return nil, status.Error(codes.Unavailable, "node not available to publish")
	}
	allowed, err := s.rbac.Evaluate(ctx, canPublishAction.For(req.GetKey()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to evaluate publish permissions: %v", err)
	}
	if !allowed {
		s.log.Warn("caller not allowed to publish")
		return nil, status.Error(codes.PermissionDenied, "not allowed")
	}
	if meshdb.IsReservedPrefix(req.GetKey()) {
		return nil, status.Errorf(codes.InvalidArgument, "key %q is reserved", req.GetKey())
	}
	// TODO: Validate key and value and check for overlaps and other issues.
	err = s.raft.Storage().PutValue(ctx, req.GetKey(), req.GetValue(), req.GetTtl().AsDuration())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error publishing: %v", err)
	}
	return &v1.PublishResponse{}, nil
}
