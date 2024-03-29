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

// Package leaderproxy provides a gRPC interceptor that proxies requests to the leader node.
package leaderproxy

import (
	"io"
	"log/slog"

	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// Interceptor is the leaderproxy interceptor.
type Interceptor struct {
	nodeID    types.NodeID
	consensus storage.Consensus
	dialer    Dialer
	network   context.Network
}

// Dialer is the interface required for the leader proxy interceptor.
type Dialer interface {
	transport.LeaderDialer
	transport.NodeDialer
}

// New returns a new leader proxy interceptor.
func New(nodeID types.NodeID, consensus storage.Consensus, dialer Dialer, network context.Network) *Interceptor {
	return &Interceptor{
		nodeID:    nodeID,
		consensus: consensus,
		dialer:    dialer,
		network:   network,
	}
}

// UnaryInterceptor returns a gRPC unary interceptor that proxies requests to the leader node.
func (i *Interceptor) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Fast path - if we are the leader, it doesn't make sense to proxy the request.
		// However, this could be a place to centralize checking the source address of the request.
		log := context.LoggerFrom(ctx)
		if i.consensus.IsLeader() {
			log.Debug("Currently the leader, handling request locally", slog.String("method", info.FullMethod))
			return handler(ctx, req)
		}
		if RouteRequiresInNetworkSource(info.FullMethod) {
			if !context.IsInNetwork(ctx, i.network) {
				addr, _ := context.PeerAddrFrom(ctx)
				log.Warn("Received request from out of network", slog.String("peer", addr.String()), slog.String("method", info.FullMethod))
				return nil, status.Errorf(codes.PermissionDenied, "request is not in-network")
			}
		}
		policy, ok := MethodPolicyMap[info.FullMethod]
		if ok {
			switch policy {
			case RequireLocal:
				log.Debug("Request requires local handling", slog.String("method", info.FullMethod))
				return handler(ctx, req)
			case AllowNonLeader:
				log.Debug("Request allows non-leader handling", slog.String("method", info.FullMethod))
				if HasPreferLeaderMeta(ctx) {
					log.Debug("Requestor prefers leader handling", slog.String("method", info.FullMethod))
					return i.proxyUnaryToLeader(ctx, req, info, handler)
				}
				return handler(ctx, req)
			}
		}
		return i.proxyUnaryToLeader(ctx, req, info, handler)
	}
}

// StreamInterceptor returns a gRPC stream interceptor that proxies requests to the leader node.
func (i *Interceptor) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		log := context.LoggerFrom(ss.Context())
		if i.consensus.IsLeader() {
			log.Debug("Currently the leader, handling stream locally", slog.String("method", info.FullMethod))
			return handler(srv, ss)
		}
		if RouteRequiresInNetworkSource(info.FullMethod) {
			if !context.IsInNetwork(ss.Context(), i.network) {
				addr, _ := context.PeerAddrFrom(ss.Context())
				log.Warn("Received request from out of network", slog.String("peer", addr.String()), slog.String("method", info.FullMethod))
				return status.Errorf(codes.PermissionDenied, "request is not in-network")
			}
		}
		policy, ok := MethodPolicyMap[info.FullMethod]
		if ok {
			switch policy {
			case RequireLocal:
				log.Debug("Stream requires local handling", slog.String("method", info.FullMethod))
				return handler(srv, ss)
			case AllowNonLeader:
				log.Debug("Stream allows non-leader handling", slog.String("method", info.FullMethod))
				if HasPreferLeaderMeta(ss.Context()) {
					log.Debug("Requestor prefers leader handling of stream", slog.String("method", info.FullMethod))
					return i.proxyStreamToLeader(srv, ss, info, handler)
				}
				return handler(srv, ss)
			}
		}
		return i.proxyStreamToLeader(srv, ss, info, handler)
	}
}

func (i *Interceptor) proxyUnaryToLeader(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	conn, err := i.dialer.DialLeader(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	ctx = metadata.AppendToOutgoingContext(ctx, ProxiedFromMeta, i.nodeID.String())
	if peer, ok := context.AuthenticatedCallerFrom(ctx); ok {
		ctx = metadata.AppendToOutgoingContext(ctx, ProxiedForMeta, peer)
	}
	switch info.FullMethod {
	// Membership API
	case v1.Membership_Join_FullMethodName:
		return v1.NewMembershipClient(conn).Join(ctx, req.(*v1.JoinRequest))
	case v1.Membership_Update_FullMethodName:
		return v1.NewMembershipClient(conn).Update(ctx, req.(*v1.UpdateRequest))
	case v1.Membership_Leave_FullMethodName:
		return v1.NewMembershipClient(conn).Leave(ctx, req.(*v1.LeaveRequest))
	case v1.Membership_Apply_FullMethodName:
		return v1.NewMembershipClient(conn).Apply(ctx, req.(*v1.RaftLogEntry))
	case v1.Membership_GetCurrentConsensus_FullMethodName:
		return v1.NewMembershipClient(conn).GetCurrentConsensus(ctx, req.(*v1.StorageConsensusRequest))

	// Node API
	case v1.Node_GetStatus_FullMethodName:
		return v1.NewNodeClient(conn).GetStatus(ctx, req.(*v1.GetStatusRequest))

	//Storage API
	case v1.StorageQueryService_Query_FullMethodName:
		return v1.NewStorageQueryServiceClient(conn).Query(ctx, req.(*v1.QueryRequest))
	case v1.StorageQueryService_Publish_FullMethodName:
		return v1.NewStorageQueryServiceClient(conn).Publish(ctx, req.(*v1.PublishRequest))

	// Mesh API
	case v1.Mesh_GetNode_FullMethodName:
		return v1.NewMeshClient(conn).GetNode(ctx, req.(*v1.GetNodeRequest))
	case v1.Mesh_ListNodes_FullMethodName:
		return v1.NewMeshClient(conn).ListNodes(ctx, req.(*emptypb.Empty))
	case v1.Mesh_GetMeshGraph_FullMethodName:
		return v1.NewMeshClient(conn).GetMeshGraph(ctx, req.(*emptypb.Empty))

	// Admin API
	case v1.Admin_PutRole_FullMethodName:
		return v1.NewAdminClient(conn).PutRole(ctx, req.(*v1.Role))
	case v1.Admin_DeleteRole_FullMethodName:
		return v1.NewAdminClient(conn).DeleteRole(ctx, req.(*v1.Role))
	case v1.Admin_GetRole_FullMethodName:
		return v1.NewAdminClient(conn).GetRole(ctx, req.(*v1.Role))
	case v1.Admin_ListRoles_FullMethodName:
		return v1.NewAdminClient(conn).ListRoles(ctx, req.(*emptypb.Empty))

	case v1.Admin_PutRoleBinding_FullMethodName:
		return v1.NewAdminClient(conn).PutRoleBinding(ctx, req.(*v1.RoleBinding))
	case v1.Admin_DeleteRoleBinding_FullMethodName:
		return v1.NewAdminClient(conn).DeleteRoleBinding(ctx, req.(*v1.RoleBinding))
	case v1.Admin_GetRoleBinding_FullMethodName:
		return v1.NewAdminClient(conn).GetRoleBinding(ctx, req.(*v1.RoleBinding))
	case v1.Admin_ListRoleBindings_FullMethodName:
		return v1.NewAdminClient(conn).ListRoleBindings(ctx, req.(*emptypb.Empty))

	case v1.Admin_PutGroup_FullMethodName:
		return v1.NewAdminClient(conn).PutGroup(ctx, req.(*v1.Group))
	case v1.Admin_DeleteGroup_FullMethodName:
		return v1.NewAdminClient(conn).DeleteGroup(ctx, req.(*v1.Group))
	case v1.Admin_GetGroup_FullMethodName:
		return v1.NewAdminClient(conn).GetGroup(ctx, req.(*v1.Group))
	case v1.Admin_ListGroups_FullMethodName:
		return v1.NewAdminClient(conn).ListGroups(ctx, req.(*emptypb.Empty))

	case v1.Admin_PutNetworkACL_FullMethodName:
		return v1.NewAdminClient(conn).PutNetworkACL(ctx, req.(*v1.NetworkACL))
	case v1.Admin_DeleteNetworkACL_FullMethodName:
		return v1.NewAdminClient(conn).DeleteNetworkACL(ctx, req.(*v1.NetworkACL))
	case v1.Admin_GetNetworkACL_FullMethodName:
		return v1.NewAdminClient(conn).GetNetworkACL(ctx, req.(*v1.NetworkACL))
	case v1.Admin_ListNetworkACLs_FullMethodName:
		return v1.NewAdminClient(conn).ListNetworkACLs(ctx, req.(*emptypb.Empty))

	case v1.Admin_PutRoute_FullMethodName:
		return v1.NewAdminClient(conn).PutRoute(ctx, req.(*v1.Route))
	case v1.Admin_DeleteRoute_FullMethodName:
		return v1.NewAdminClient(conn).DeleteRoute(ctx, req.(*v1.Route))
	case v1.Admin_GetRoute_FullMethodName:
		return v1.NewAdminClient(conn).GetRoute(ctx, req.(*v1.Route))
	case v1.Admin_ListRoutes_FullMethodName:
		return v1.NewAdminClient(conn).ListRoutes(ctx, req.(*emptypb.Empty))

	case v1.Admin_PutEdge_FullMethodName:
		return v1.NewAdminClient(conn).PutEdge(ctx, req.(*v1.MeshEdge))
	case v1.Admin_DeleteEdge_FullMethodName:
		return v1.NewAdminClient(conn).DeleteEdge(ctx, req.(*v1.MeshEdge))
	case v1.Admin_GetEdge_FullMethodName:
		return v1.NewAdminClient(conn).GetEdge(ctx, req.(*v1.MeshEdge))
	case v1.Admin_ListEdges_FullMethodName:
		return v1.NewAdminClient(conn).ListEdges(ctx, req.(*emptypb.Empty))

	default:
		return nil, status.Errorf(codes.Unimplemented, "unimplemented leader-proxy method: %s", info.FullMethod)
	}
}

func (i *Interceptor) proxyStreamToLeader(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	conn, err := i.dialer.DialLeader(ss.Context())
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx := metadata.AppendToOutgoingContext(ss.Context(), ProxiedFromMeta, i.nodeID.String())
	if peer, ok := context.AuthenticatedCallerFrom(ctx); ok {
		ctx = metadata.AppendToOutgoingContext(ctx, ProxiedForMeta, peer)
	}
	switch info.FullMethod {

	// Node API
	case v1.Node_NegotiateDataChannel_FullMethodName:
		client := v1.NewNodeClient(conn)
		stream, err := client.NegotiateDataChannel(ctx)
		if err != nil {
			return err
		}
		return proxyStream[v1.DataChannelNegotiation, v1.DataChannelNegotiation](ctx, ss, stream)

	// Membership API
	case v1.Membership_SubscribePeers_FullMethodName:
		client := v1.NewMembershipClient(conn)
		var req *v1.SubscribePeersRequest
		if err := ss.RecvMsg(&req); err != nil {
			return err
		}
		stream, err := client.SubscribePeers(ctx, req)
		if err != nil {
			return err
		}
		return proxyStream[v1.SubscribePeersRequest, v1.PeerConfigurations](ctx, ss, stream)

	// WebRTC API
	case v1.WebRTC_StartDataChannel_FullMethodName:
		client := v1.NewWebRTCClient(conn)
		stream, err := client.StartDataChannel(ctx)
		if err != nil {
			return err
		}
		return proxyStream[v1.StartDataChannelRequest, v1.DataChannelOffer](ctx, ss, stream)

	// Storage API
	case v1.StorageQueryService_Subscribe_FullMethodName:
		client := v1.NewStorageQueryServiceClient(conn)
		var req *v1.SubscribeRequest
		if err := ss.RecvMsg(&req); err != nil {
			return err
		}
		stream, err := client.Subscribe(ctx, req)
		if err != nil {
			return err
		}
		return proxyStream[v1.SubscribeRequest, v1.SubscriptionEvent](ctx, ss, stream)

	default:
		return status.Errorf(codes.Unimplemented, "unimplemented leader-proxy method: %s", info.FullMethod)
	}
}

func proxyStream[S, R any](ctx context.Context, ss grpc.ServerStream, cs grpc.ClientStream) error {
	defer func() {
		if err := cs.CloseSend(); err != nil {
			context.LoggerFrom(ctx).Error("error closing client stream", slog.String("error", err.Error()))
		}
	}()
	go func() {
		for {
			var msg R
			err := cs.RecvMsg(&msg)
			if err != nil {
				if err == io.EOF {
					return
				}
				context.LoggerFrom(ctx).Error("error receiving message from leader", slog.String("error", err.Error()))
				return
			}
			if err := ss.SendMsg(msg); err != nil {
				context.LoggerFrom(ctx).Error("error sending message to client", slog.String("error", err.Error()))
				return
			}
		}
	}()
	for {
		var msg S
		if err := ss.RecvMsg(&msg); err != nil {
			if err == io.EOF {
				return nil
			}
			context.LoggerFrom(ctx).Error("error receiving message from client", slog.String("error", err.Error()))
			return err
		}
		if err := cs.SendMsg(msg); err != nil {
			context.LoggerFrom(ctx).Error("error sending message to leader", slog.String("error", err.Error()))
			return err
		}
	}
}
