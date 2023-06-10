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

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// Context is an alias to context.Context for convenience and to avoid
// confusion with the context package.
type Context = context.Context

type contextKey string

const authenticatedCallerKey = contextKey("authenticatedCaller")

// WithAuthenticatedCaller returns a context with the authenticated caller set.
func WithAuthenticatedCaller(ctx Context, id string) Context {
	return context.WithValue(ctx, authenticatedCallerKey, id)
}

// AuthenticatedCallerFrom returns the authenticated caller from the context.
func AuthenticatedCallerFrom(ctx Context) (string, bool) {
	id, ok := ctx.Value(authenticatedCallerKey).(string)
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
