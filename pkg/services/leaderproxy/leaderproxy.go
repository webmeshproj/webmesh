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
	"fmt"
	"net"
	"strconv"

	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"gitlab.com/webmesh/node/pkg/services/node/peers"
	"gitlab.com/webmesh/node/pkg/store"
)

type Interceptor struct {
	store     store.Store
	tlsConfig *tls.Config
	logger    *slog.Logger
}

// New returns a new leader proxy interceptor.
func New(store store.Store, tlsConfig *tls.Config, logger *slog.Logger) *Interceptor {
	return &Interceptor{
		store:     store,
		tlsConfig: tlsConfig,
		logger:    logger,
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
	leaderAddr, err := i.getLeaderAddr(ctx)
	if err != nil {
		i.logger.Error("could not get leader address", slog.String("error", err.Error()))
		return nil, status.Errorf(codes.Unavailable, "no leader available to serve the request: %s", err.Error())
	}
	i.logger.Info("proxying request to leader",
		slog.String("method", info.FullMethod),
		slog.String("leader", leaderAddr))
	var creds credentials.TransportCredentials
	if i.tlsConfig == nil {
		creds = insecure.NewCredentials()
	} else {
		creds = credentials.NewTLS(i.tlsConfig)
	}
	conn, err := grpc.DialContext(ctx, leaderAddr, grpc.WithTransportCredentials(creds))
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

func (i *Interceptor) getLeaderAddr(ctx context.Context) (string, error) {
	leader, err := i.store.Leader()
	if err != nil {
		return "", err
	}
	node, err := peers.New(i.store).Get(ctx, leader)
	if err != nil {
		return "", err
	}
	var leaderAddr string
	// Prefer IPv4
	if node.PrivateIPv4.IsValid() {
		leaderAddr = node.PrivateIPv4.Addr().String()
	} else if node.NetworkIPv6.IsValid() {
		// Use IPv6 if IPv4 is not available
		leaderAddr = node.NetworkIPv6.Addr().String()
	} else {
		return "", fmt.Errorf("no private IP address available for leader")
	}
	return net.JoinHostPort(leaderAddr, strconv.Itoa(node.GRPCPort)), nil
}
