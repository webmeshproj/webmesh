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
	"github.com/webmeshproj/webmesh/pkg/services/rbac"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

var canSubscribeAction = rbac.Actions{
	{
		Verb:     v1.RuleVerb_VERB_GET,
		Resource: v1.RuleResource_RESOURCE_PUBSUB,
	},
}

func (s *Server) Subscribe(req *v1.SubscribeRequest, srv v1.StorageQueryService_SubscribeServer) error {
	if !context.IsInNetwork(srv.Context(), s.wg) {
		addr, _ := context.PeerAddrFrom(srv.Context())
		s.log.Warn("Received Subscribe request from out of network", slog.String("peer", addr.String()))
		return status.Errorf(codes.PermissionDenied, "request is not in-network")
	}
	if !s.storage.Consensus().IsMember() {
		// In theory - non-raft members shouldn't even expose the Node service.
		return status.Error(codes.Unavailable, "current node not available to subscribe")
	}
	if !storage.IsReservedPrefix(req.GetPrefix()) {
		// Don't allow subscriptions to generic prefixes without permissions
		allowed, err := s.rbac.Evaluate(srv.Context(), canSubscribeAction.For(req.GetPrefix()))
		if err != nil {
			return status.Errorf(codes.Internal, "failed to evaluate subscribe permissions: %v", err)
		}
		if !allowed {
			s.log.Warn("caller not allowed to subscribe")
			return status.Error(codes.PermissionDenied, "not allowed")
		}
	}
	cancel, err := s.storage.MeshStorage().Subscribe(srv.Context(), req.GetPrefix(), func(key, value string) {
		err := srv.Send(&v1.SubscriptionEvent{
			Key:   key,
			Value: value,
		})
		if err != nil {
			s.log.Error("error sending subscription event", "error", err.Error())
		}
	})
	if err != nil {
		return status.Errorf(codes.Internal, "error subscribing: %v", err)
	}
	defer cancel()
	<-srv.Context().Done()
	return nil
}
