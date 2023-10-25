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

package transport

import (
	"context"
	"net/netip"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// Resolver is the interface for resolving node addresses. Implementations
// can be pre-baked for specialized cases, such as resolving node addresses
// by a specific feature. The returned type is an AddrPort to support
// resolvers that need to return port numbers.
type Resolver[T any] interface {
	// Resolve resolves the addresses for the given lookup parameters.
	Resolve(ctx context.Context, lookup T) ([]netip.AddrPort, error)
}

// NewNoopResolver returns a no-op resolver of the specified type.
func NewNoopResolver[T any]() Resolver[T] {
	return ResolverFunc[T](func(ctx context.Context, lookup T) ([]netip.AddrPort, error) {
		return nil, nil
	})
}

// ResolverFunc is a function that implements Resolver.
type ResolverFunc[T any] func(ctx context.Context, lookup T) ([]netip.AddrPort, error)

// Resolve implements Resolver.
func (f ResolverFunc[T]) Resolve(ctx context.Context, lookup T) ([]netip.AddrPort, error) {
	return f(ctx, lookup)
}

// NodeIDResolver is a resolver that resolves node addresses by node ID.
type NodeIDResolver = Resolver[types.NodeID]

// NodeIDResolverFunc is a function that implements NodeIDResolver.
type NodeIDResolverFunc = ResolverFunc[types.NodeID]

// FeatureResolver is a resolver that resolves node addresses by feature.
type FeatureResolver = Resolver[v1.Feature]

// FeatureResolverFunc is a function that implements FeatureResolver.
type FeatureResolverFunc = ResolverFunc[v1.Feature]
