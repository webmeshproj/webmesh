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

// Package context provides facilities for storing and retrieving values from context objects.
package context

import (
	"context"
	"time"

	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// Context is an alias to context.Context for convenience and to avoid
// confusion with the context package.
type Context = context.Context

// CancelFunc is an alias to context.CancelFunc for convenience and to avoid
// confusion with the context package.
type CancelFunc = context.CancelFunc

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

type logContextKey struct{}

// WithLogger returns a context with the given logger set.
func WithLogger(ctx Context, logger *slog.Logger) Context {
	return context.WithValue(ctx, logContextKey{}, logger)
}

// LoggerFrom returns the logger from the context. If no logger is set, the
// default logger is returned.
func LoggerFrom(ctx Context) *slog.Logger {
	logger, ok := ctx.Value(logContextKey{}).(*slog.Logger)
	if !ok {
		return slog.Default()
	}
	return logger
}

// LogInjectUnaryServerInterceptor returns a unary server interceptor that
// injects the logger into the context.
func LogInjectUnaryServerInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		return handler(WithLogger(ctx, logger), req)
	}
}

// LogInjectStreamServerInterceptor returns a stream server interceptor that
// injects the logger into the context.
func LogInjectStreamServerInterceptor(logger *slog.Logger) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, &logInjectServerStream{ss, logger})
	}
}

type logInjectServerStream struct {
	grpc.ServerStream
	logger *slog.Logger
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
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, false
	}
	return p.AuthInfo, p.AuthInfo != nil
}
