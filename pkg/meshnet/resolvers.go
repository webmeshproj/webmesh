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

package meshnet

import (
	"context"
	"net/netip"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// NewResolver returns a new Resolver instance.
func NewResolver(st storage.MeshDB) PeerResolver {
	return &peerResolver{st: st}
}

type peerResolver struct {
	st storage.MeshDB
}

// NodeIDResolver returns a resolver that resolves node addresses by node ID.
func (r *peerResolver) NodeIDResolver() transport.NodeIDResolver {
	return transport.NodeIDResolverFunc(func(ctx context.Context, lookup string) ([]netip.AddrPort, error) {
		node, err := r.st.Peers().Get(ctx, lookup)
		if err != nil {
			return nil, err
		}
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
func (r *peerResolver) FeatureResolver(filterFn ...PeerFilterFunc) transport.FeatureResolver {
	return transport.FeatureResolverFunc(func(ctx context.Context, lookup v1.Feature) ([]netip.AddrPort, error) {
		var addrs []netip.AddrPort
		nodes, err := r.st.Peers().List(ctx, storage.FeatureFilter(lookup))
		if err != nil {
			return nil, err
		}
		for _, node := range nodes {
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
		return addrs, err
	})
}
