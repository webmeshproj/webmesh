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

// Package leaderproxy provides a gRPC interceptor that proxies requests to the leader node.
package leaderproxy

import (
	"context"
	"crypto/tls"

	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"gitlab.com/webmesh/node/pkg/store"
)

type Interceptor struct {
	store     store.Store
	tlsConfig *tls.Config
	logger    *slog.Logger
	dialOpts  []grpc.DialOption
}

// New returns a new leader proxy interceptor.
func New(store store.Store, tlsConfig *tls.Config, logger *slog.Logger) *Interceptor {
	var creds credentials.TransportCredentials
	if tlsConfig == nil {
		creds = insecure.NewCredentials()
	} else {
		creds = credentials.NewTLS(tlsConfig)
	}
	return &Interceptor{
		store:     store,
		tlsConfig: tlsConfig,
		logger:    logger,
		dialOpts:  []grpc.DialOption{grpc.WithTransportCredentials(creds)},
	}
}

// UnaryInterceptor returns a gRPC unary interceptor that proxies requests to the leader node.
func (i *Interceptor) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		// Fast path - if we are the leader, it doesn't make sense to proxy the request.
		if i.store.IsLeader() {
			i.logger.Debug("currently the leader, handling request locally", slog.String("method", info.FullMethod))
			return handler(ctx, req)
		}
		policy, ok := MethodPolicyMap[info.FullMethod]
		if ok {
			switch policy {
			case RequireLocal:
				i.logger.Debug("request requires local handling", slog.String("method", info.FullMethod))
				return handler(ctx, req)
			case AllowNonLeader:
				i.logger.Debug("request allows non-leader handling", slog.String("method", info.FullMethod))
				if HasPreferLeaderMeta(ctx) {
					i.logger.Debug("requestor prefers leader handling", slog.String("method", info.FullMethod))
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
		if i.store.IsLeader() {
			i.logger.Debug("currently the leader, handling stream locally", slog.String("method", info.FullMethod))
			return handler(srv, ss)
		}
		// TODO: Implement if/when streams are being used
		return status.Errorf(codes.Unavailable, "no leader available to serve the request")
	}
}

func (i *Interceptor) proxyUnaryToLeader(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	leaderAddr, err := i.store.LeaderRPCAddr(ctx)
	if err != nil {
		i.logger.Error("could not get leader address", slog.String("error", err.Error()))
		return nil, status.Errorf(codes.Unavailable, "no leader available to serve the request: %s", err.Error())
	}
	i.logger.Info("proxying request to leader",
		slog.String("method", info.FullMethod),
		slog.String("leader", leaderAddr))
	conn, err := grpc.DialContext(ctx, leaderAddr, i.dialOpts...)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "could not connect to leader to serve the request: %s", err.Error())
	}
	defer conn.Close()
	var out any
	err = conn.Invoke(ctx, info.FullMethod, req, &out)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not invoke RPC on the leader: %s", err.Error())
	}
	return out, nil
}
