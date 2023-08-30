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

// Package context provides facilities for storing and retrieving values from context objects.
package context

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// Logger is an alias to slog.Logger for convenience.
type Logger = *slog.Logger

// Context is an alias to context.Context for convenience and to avoid
// confusion with the context package.
type Context = context.Context

// CancelFunc is an alias to context.CancelFunc for convenience and to avoid
// confusion with the context package.
type CancelFunc = context.CancelFunc

// Canceled is an alias to context.Canceled for convenience and to avoid
// confusion with the context package.
var Canceled = context.Canceled

// Background returns a background context.
func Background() Context {
	return context.Background()
}

// WithTimeout returns a context with the given timeout.
func WithTimeout(ctx Context, timeout time.Duration) (Context, CancelFunc) {
	return context.WithTimeout(ctx, timeout)
}

// WithDeadline returns a context with the given deadline.
func WithDeadline(ctx Context, deadline time.Time) (Context, CancelFunc) {
	return context.WithDeadline(ctx, deadline)
}

// WithCancel returns a context with the given cancel function.
func WithCancel(ctx Context) (Context, CancelFunc) {
	return context.WithCancel(ctx)
}

type logContextKey struct{}

// WithLogger returns a context with the given logger set.
func WithLogger(ctx Context, logger Logger) Context {
	return context.WithValue(ctx, logContextKey{}, logger)
}

// LoggerFrom returns the logger from the context. If no logger is set, the
// default logger is returned.
func LoggerFrom(ctx Context) Logger {
	logger, ok := ctx.Value(logContextKey{}).(*slog.Logger)
	if !ok {
		return slog.Default()
	}
	return logger
}

// LogInjectUnaryServerInterceptor returns a unary server interceptor that
// injects the logger into the context.
func LogInjectUnaryServerInterceptor(logger Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		return handler(WithLogger(ctx, logger), req)
	}
}

// LogInjectStreamServerInterceptor returns a stream server interceptor that
// injects the logger into the context.
func LogInjectStreamServerInterceptor(logger Logger) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, &logInjectServerStream{ss, logger})
	}
}

type logInjectServerStream struct {
	grpc.ServerStream
	logger Logger
}

func (ss *logInjectServerStream) Context() Context {
	return WithLogger(ss.ServerStream.Context(), ss.logger)
}

type authenticatedCallerKey struct{}

// WithAuthenticatedCaller returns a context with the authenticated caller set.
func WithAuthenticatedCaller(ctx Context, id string) Context {
	return context.WithValue(ctx, authenticatedCallerKey{}, id)
}

// AuthenticatedCallerFrom returns the authenticated caller from the context.
func AuthenticatedCallerFrom(ctx Context) (string, bool) {
	id, ok := ctx.Value(authenticatedCallerKey{}).(string)
	return id, ok
}

// MetadataFrom is a convenience wrapper around retrieving the gRPC metadata
// from an incoming request.
func MetadataFrom(ctx Context) (map[string][]string, bool) {
	return metadata.FromIncomingContext(ctx)
}

// AuthInfoFrom is a convenience wrapper around retrieving the gRPC authentication info
// from an incoming request.
func AuthInfoFrom(ctx Context) (credentials.AuthInfo, bool) {
	p, ok := PeerFrom(ctx)
	if !ok {
		return nil, false
	}
	return p.AuthInfo, p.AuthInfo != nil
}

// PeerAddrFrom is a convenience wrapper around retrieving the gRPC peer address
// from an incoming request.
func PeerAddrFrom(ctx Context) (netip.Addr, bool) {
	p, ok := PeerFrom(ctx)
	if !ok {
		return netip.Addr{}, false
	}
	addrport, err := netip.ParseAddrPort(p.Addr.String())
	if err != nil {
		LoggerFrom(ctx).Warn("failed to parse peer address", "error", err.Error())
		return netip.Addr{}, false
	}
	return addrport.Addr(), true
}

// Network is an interface that returns the IPv4 and IPv6 networks of the mesh.
type Network interface {
	NetworkV4() netip.Prefix
	NetworkV6() netip.Prefix
}

// IsInNetwork returns true if the given context is from a peer in the given
// network.
func IsInNetwork(ctx Context, network Network) bool {
	addr, ok := PeerAddrFrom(ctx)
	if !ok {
		return false
	}
	if addr.Is4() {
		return network.NetworkV4().Contains(addr)
	}
	return network.NetworkV6().Contains(addr)
}

// PeerFrom is a convenience wrapper around retrieving the gRPC peer info
// from an incoming request.
func PeerFrom(ctx Context) (*peer.Peer, bool) {
	return peer.FromContext(ctx)
}
