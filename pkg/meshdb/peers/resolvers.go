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

package peers

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/encoding/protojson"

	peergraph "github.com/webmeshproj/webmesh/pkg/meshdb/graph"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// FilterFunc is a function that can be used to filter responses returned by a resolver.
type FilterFunc func(peergraph.MeshNode) bool

// Resolver provides facilities for creating various transport.Resolver instances.
type Resolver interface {
	// NodeIDResolver returns a resolver that resolves node addresses by node ID.
	NodeIDResolver() transport.NodeIDResolver
	// FeatureResolver returns a resolver that resolves node addresses by feature.
	FeatureResolver(filterFn ...FilterFunc) transport.FeatureResolver
}

// NewResolver returns a new Resolver instance.
func NewResolver(st storage.MeshStorage) Resolver {
	return &peerResolver{st: st}
}

type peerResolver struct {
	st storage.MeshStorage
}

// NodeIDResolver returns a resolver that resolves node addresses by node ID.
func (r *peerResolver) NodeIDResolver() transport.NodeIDResolver {
	return transport.NodeIDResolverFunc(func(ctx context.Context, lookup string) ([]netip.AddrPort, error) {
		key := peergraph.NodesPrefix.For([]byte(lookup))
		val, err := r.st.GetValue(ctx, key)
		if err != nil {
			return nil, err
		}
		mnode := &v1.MeshNode{}
		err = protojson.Unmarshal([]byte(val), mnode)
		if err != nil {
			return nil, fmt.Errorf("unmarshal node: %w", err)
		}
		node := peergraph.MeshNode{MeshNode: mnode}
		var addrs []netip.AddrPort
		if addr := node.PrivateAddrV4(); addr.IsValid() {
			addrs = append(addrs, netip.AddrPortFrom(addr.Addr(), 0))
		}
		if addr := node.PrivateAddrV6(); addr.IsValid() {
			addrs = append(addrs, netip.AddrPortFrom(addr.Addr(), 0))
		}
		return addrs, nil
	})
}

// FeatureResolver returns a resolver that resolves node addresses by feature.
func (r *peerResolver) FeatureResolver(filterFn ...FilterFunc) transport.FeatureResolver {
	return transport.FeatureResolverFunc(func(ctx context.Context, lookup v1.Feature) ([]netip.AddrPort, error) {
		var addrs []netip.AddrPort
		err := r.st.IterPrefix(ctx, peergraph.NodesPrefix, func(key, val []byte) error {
			if bytes.Equal(key, peergraph.NodesPrefix) {
				return nil
			}
			mnode := &v1.MeshNode{}
			err := protojson.Unmarshal([]byte(val), mnode)
			if err != nil {
				return fmt.Errorf("unmarshal node: %w", err)
			}
			node := peergraph.MeshNode{MeshNode: mnode}
			for _, fn := range filterFn {
				if !fn(node) {
					return nil
				}
			}
			if node.HasFeature(lookup) {
				switch lookup {
				// Return the DNS port for DNS features
				case v1.Feature_MESH_DNS, v1.Feature_FORWARD_MESH_DNS:
					if addr := node.PrivateDNSAddrV4(); addr.IsValid() {
						addrs = append(addrs, addr)
					}
					if addr := node.PrivateDNSAddrV6(); addr.IsValid() {
						addrs = append(addrs, addr)
					}
				// Return the TURN port for TURN features
				case v1.Feature_TURN_SERVER:
					if addr := node.PrivateTURNAddrV4(); addr.IsValid() {
						addrs = append(addrs, addr)
					}
					if addr := node.PrivateTURNAddrV6(); addr.IsValid() {
						addrs = append(addrs, addr)
					}
				// Return the Storage port for storage features
				case v1.Feature_STORAGE_PROVIDER:
					if addr := node.PrivateStorageAddrV4(); addr.IsValid() {
						addrs = append(addrs, addr)
					}
					if addr := node.PrivateStorageAddrV6(); addr.IsValid() {
						addrs = append(addrs, addr)
					}
				// ICE negotiation is a special case where we use the RPC port,
				// but prioritize a primary endpoint if one is available.
				case v1.Feature_ICE_NEGOTIATION:
					if addr := node.PublicRPCAddr(); addr.IsValid() {
						addrs = append(addrs, addr)
					} else {
						// Fall back to private RPC address if no public address is available.
						if addr := node.PrivateRPCAddrV4(); addr.IsValid() {
							addrs = append(addrs, addr)
						}
						if addr := node.PrivateRPCAddrV6(); addr.IsValid() {
							addrs = append(addrs, addr)
						}
					}
				// All other features use the RPC port for now.
				default:
					if addr := node.PrivateRPCAddrV4(); addr.IsValid() {
						addrs = append(addrs, addr)
					}
					if addr := node.PrivateRPCAddrV6(); addr.IsValid() {
						addrs = append(addrs, addr)
					}
				}
			}
			return nil
		})
		if len(addrs) == 0 {
			err = fmt.Errorf("no nodes found with feature %s", lookup)
		}
		return addrs, err
	})
}
