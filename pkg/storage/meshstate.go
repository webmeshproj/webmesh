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
	"context"
	"net/netip"

	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// MeshState is the interface for querying mesh state.
type MeshState interface {
	// GetIPv6Prefix returns the IPv6 prefix.
	GetIPv6Prefix(ctx context.Context) (netip.Prefix, error)
	// SetIPv6Prefix sets the IPv6 prefix.
	SetIPv6Prefix(ctx context.Context, prefix netip.Prefix) error
	// GetIPv4Prefix returns the IPv4 prefix.
	GetIPv4Prefix(ctx context.Context) (netip.Prefix, error)
	// SetIPv4Prefix sets the IPv4 prefix.
	SetIPv4Prefix(ctx context.Context, prefix netip.Prefix) error
	// GetMeshDomain returns the mesh domain.
	GetMeshDomain(ctx context.Context) (string, error)
	// SetMeshDomain sets the mesh domain.
	SetMeshDomain(ctx context.Context, domain string) error
	// GetMeshState returns the full mesh state.
	GetMeshState(ctx context.Context) (types.NetworkState, error)
}
