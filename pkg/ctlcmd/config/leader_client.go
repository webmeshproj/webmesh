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

// Package config contains the wmctl CLI tool configuration.
package config

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// LeaderUnaryClientInterceptor returns a gRPC unary client interceptor that
// adds the prefer-leader metadata to the outgoing context.
func LeaderUnaryClientInterceptor() grpc.UnaryClientInterceptor {
	return func(parentCtx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		md := metadata.Pairs("prefer-leader", "true")
		ctx := metadata.NewOutgoingContext(parentCtx, md)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// LeaderStreamClientInterceptor returns a gRPC stream client interceptor that
// adds the prefer-leader metadata to the outgoing context.
func LeaderStreamClientInterceptor() grpc.StreamClientInterceptor {
	return func(parentCtx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		md := metadata.Pairs("prefer-leader", "true")
		ctx := metadata.NewOutgoingContext(parentCtx, md)
		return streamer(ctx, desc, cc, method, opts...)
	}
}
