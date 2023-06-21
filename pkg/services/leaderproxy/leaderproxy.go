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

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/store"
)

type Interceptor struct {
	store    store.Store
	dialOpts []grpc.DialOption
}

// New returns a new leader proxy interceptor.
func New(store store.Store, dialOpts []grpc.DialOption) *Interceptor {
	return &Interceptor{
		store:    store,
		dialOpts: dialOpts,
	}
}

// UnaryInterceptor returns a gRPC unary interceptor that proxies requests to the leader node.
func (i *Interceptor) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Fast path - if we are the leader, it doesn't make sense to proxy the request.
		log := context.LoggerFrom(ctx)
		if i.store.IsLeader() {
			log.Debug("currently the leader, handling request locally", slog.String("method", info.FullMethod))
			return handler(ctx, req)
		}
		policy, ok := MethodPolicyMap[info.FullMethod]
		if ok {
			switch policy {
			case RequireLocal:
				log.Debug("request requires local handling", slog.String("method", info.FullMethod))
				return handler(ctx, req)
			case AllowNonLeader:
				log.Debug("request allows non-leader handling", slog.String("method", info.FullMethod))
				if HasPreferLeaderMeta(ctx) {
					log.Debug("requestor prefers leader handling", slog.String("method", info.FullMethod))
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
		if i.store.IsLeader() {
			log.Debug("currently the leader, handling stream locally", slog.String("method", info.FullMethod))
			return handler(srv, ss)
		}
		policy, ok := MethodPolicyMap[info.FullMethod]
		if ok {
			switch policy {
			case RequireLocal:
				log.Debug("stream requires local handling", slog.String("method", info.FullMethod))
				return handler(srv, ss)
			case AllowNonLeader:
				log.Debug("stream allows non-leader handling", slog.String("method", info.FullMethod))
				if HasPreferLeaderMeta(ss.Context()) {
					log.Debug("requestor prefers leader handling of stream", slog.String("method", info.FullMethod))
					return i.proxyStreamToLeader(srv, ss, info, handler)
				}
				return handler(srv, ss)
			}
		}
		return i.proxyStreamToLeader(srv, ss, info, handler)
	}
}

func (i *Interceptor) proxyUnaryToLeader(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	conn, err := i.newLeaderConn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	ctx = metadata.AppendToOutgoingContext(ctx, ProxiedFromMeta, string(i.store.ID()))
	if peer, ok := context.AuthenticatedCallerFrom(ctx); ok {
		ctx = metadata.AppendToOutgoingContext(ctx, ProxiedForMeta, peer)
	}
	switch info.FullMethod {
	// Node API
	case v1.Node_Join_FullMethodName:
		return v1.NewNodeClient(conn).Join(ctx, req.(*v1.JoinRequest))
	case v1.Node_Leave_FullMethodName:
		return v1.NewNodeClient(conn).Leave(ctx, req.(*v1.LeaveRequest))
	case v1.Node_Snapshot_FullMethodName:
		return v1.NewNodeClient(conn).Snapshot(ctx, req.(*v1.SnapshotRequest))
	case v1.Node_GetStatus_FullMethodName:
		return v1.NewNodeClient(conn).GetStatus(ctx, req.(*v1.GetStatusRequest))

	// Mesh API
	case v1.Mesh_GetNode_FullMethodName:
		return v1.NewMeshClient(conn).GetNode(ctx, req.(*v1.GetNodeRequest))
	case v1.Mesh_ListNodes_FullMethodName:
		return v1.NewMeshClient(conn).ListNodes(ctx, req.(*emptypb.Empty))
	case v1.Mesh_GetMeshGraph_FullMethodName:
		return v1.NewMeshClient(conn).GetMeshGraph(ctx, req.(*emptypb.Empty))

	// Peer Discovery API
	case v1.PeerDiscovery_ListPeers_FullMethodName:
		return v1.NewPeerDiscoveryClient(conn).ListPeers(ctx, req.(*emptypb.Empty))

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
	conn, err := i.newLeaderConn(ss.Context())
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx := metadata.AppendToOutgoingContext(ss.Context(), ProxiedFromMeta, string(i.store.ID()))
	if peer, ok := context.AuthenticatedCallerFrom(ctx); ok {
		ctx = metadata.AppendToOutgoingContext(ctx, ProxiedForMeta, peer)
	}
	switch info.FullMethod {
	case v1.WebRTC_StartDataChannel_FullMethodName:
		client := v1.NewWebRTCClient(conn)
		stream, err := client.StartDataChannel(ctx)
		if err != nil {
			return err
		}
		return proxyStream[v1.StartDataChannelRequest, v1.DataChannelOffer](ctx, ss, stream)
	default:
		return status.Errorf(codes.Unimplemented, "unimplemented leader-proxy method: %s", info.FullMethod)
	}
}

func (i *Interceptor) newLeaderConn(ctx context.Context) (*grpc.ClientConn, error) {
	leaderAddr, err := i.store.LeaderRPCAddr(ctx)
	if err != nil {
		context.LoggerFrom(ctx).Error("could not get leader address", slog.String("error", err.Error()))
		return nil, status.Errorf(codes.Unavailable, "no leader available to serve the request: %s", err.Error())
	}
	context.LoggerFrom(ctx).Info("dialing leader to serve request", slog.String("leader", leaderAddr))
	conn, err := grpc.DialContext(ctx, leaderAddr, i.dialOpts...)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "could not connect to leader to serve the request: %s", err.Error())
	}
	return conn, nil
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
