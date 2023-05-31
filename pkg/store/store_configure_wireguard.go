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

package store

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/webmeshproj/node/pkg/firewall"
	"github.com/webmeshproj/node/pkg/meshdb/peers"
	"github.com/webmeshproj/node/pkg/util"
	"github.com/webmeshproj/node/pkg/wireguard"
	"github.com/webmeshproj/node/pkg/wireguard/system"
)

func (s *store) ConfigureWireguard(ctx context.Context, key wgtypes.Key, addressv4, addressv6, meshNetworkV6 netip.Prefix) error {
	s.wgmux.Lock()
	defer s.wgmux.Unlock()
	s.wgopts.NetworkV4 = addressv4
	s.wgopts.NetworkV6 = addressv6
	s.wgopts.IsPublic = s.opts.NodeEndpoint != ""
	s.log.Info("configuring wireguard interface", slog.Any("options", s.wgopts))
	var err error
	if s.fw == nil {
		s.fw, err = firewall.New(&firewall.Options{
			DefaultPolicy: firewall.PolicyAccept,
			WireguardPort: uint16(s.wgopts.ListenPort),
			RaftPort:      uint16(s.sl.ListenPort()),
			GRPCPort:      uint16(s.opts.GRPCAdvertisePort),
		})
		if err != nil {
			return fmt.Errorf("new firewall: %w", err)
		}
	}
	if s.wg == nil {
		s.wg, err = wireguard.New(ctx, s.wgopts)
		if err != nil {
			return fmt.Errorf("new wireguard: %w", err)
		}
		err = s.wg.Up(ctx)
		if err != nil {
			return fmt.Errorf("wireguard up: %w", err)
		}
	}
	err = s.wg.Configure(ctx, key, s.wgopts.ListenPort)
	if err != nil {
		return fmt.Errorf("wireguard configure: %w", err)
	}
	if addressv4.IsValid() {
		err = s.wg.AddRoute(ctx, addressv4)
		if err != nil && !system.IsRouteExists(err) {
			return fmt.Errorf("wireguard add ipv4 route: %w", err)
		}
	}
	if addressv6.IsValid() {
		err = s.wg.AddRoute(ctx, addressv6)
		if err != nil && !system.IsRouteExists(err) {
			return fmt.Errorf("wireguard add ipv6 route: %w", err)
		}
	}
	if meshNetworkV6.IsValid() {
		err = s.wg.AddRoute(ctx, meshNetworkV6)
		if err != nil && !system.IsRouteExists(err) {
			return fmt.Errorf("wireguard add mesh network route: %w", err)
		}
	}
	err = s.fw.AddWireguardForwarding(ctx, s.wg.Name())
	if err != nil {
		return fmt.Errorf("failed to add wireguard forwarding rule: %w", err)
	}
	if s.wgopts.Masquerade {
		err = s.fw.AddMasquerade(ctx, s.wg.Name())
		if err != nil {
			return fmt.Errorf("failed to add masquerade rule: %w", err)
		}
	}
	return nil
}

func (s *store) RefreshWireguardPeers(ctx context.Context) error {
	if s.wg == nil {
		return nil
	}
	s.wgmux.Lock()
	defer s.wgmux.Unlock()
	err := s.walkMeshDescendants(peers.NewGraph(s))
	if err != nil {
		s.log.Error("walk mesh descendants", slog.String("error", err.Error()))
		return nil
	}
	return nil
}

func (s *store) walkMeshDescendants(graph peers.Graph) error {
	// TODO: Check for peers no longer in the mesh and remove them
	// This is currently hacked into the FSM apply function
	adjacencyMap, err := graph.AdjacencyMap()
	if err != nil {
		return fmt.Errorf("adjacency map: %w", err)
	}
	slog.Debug("current adjacency map", slog.Any("map", adjacencyMap))
	ourDescendants := adjacencyMap[string(s.nodeID)]
	if len(ourDescendants) == 0 {
		s.log.Debug("no descendants found in mesh DAG")
		return nil
	}
	var localCIDRs util.PrefixList
	if s.opts.ZoneAwarenessID != "" {
		s.log.Debug("using zone awareness, collecting local CIDRs")
		localCIDRs, err = util.DetectEndpoints(context.Background(), util.EndpointDetectOpts{
			DetectPrivate: true,
			DetectIPv6:    !s.opts.NoIPv6,
		})
		s.log.Debug("detected local CIDRs", slog.Any("cidrs", localCIDRs.Strings()))
		if err != nil {
			return fmt.Errorf("detect endpoints: %w", err)
		}
	}
	for descendant, edge := range ourDescendants {
		desc, _ := graph.Vertex(descendant)
		// Each direct child is a wireguard peer
		peer := &wireguard.Peer{
			ID:         desc.ID,
			PublicKey:  desc.PublicKey,
			AllowedIPs: make([]netip.Prefix, 0),
		}
		// Determine the preferred endpoint for this peer
		var primaryEndpoint string
		if desc.PrimaryEndpoint != "" {
			for _, ep := range desc.WireGuardEndpoints {
				if strings.HasPrefix(ep, desc.PrimaryEndpoint) {
					primaryEndpoint = ep
					break
				}
			}
		}
		if primaryEndpoint == "" && len(desc.WireGuardEndpoints) > 0 {
			primaryEndpoint = desc.WireGuardEndpoints[0]
		}
		// Resolve the endpoint and check for zone awareness
		if primaryEndpoint != "" {
			addr, err := net.ResolveUDPAddr("udp", primaryEndpoint)
			if err != nil {
				s.log.Error("could not resolve primary udp addr", slog.String("error", err.Error()))
			} else {
				if addr.AddrPort().Addr().Is4In6() {
					// This is an IPv4 address masquerading as an IPv6 address.
					// We need to convert it to a real IPv4 address.
					// This is a workaround for a bug in Go's net package.
					addr = &net.UDPAddr{
						IP:   addr.IP.To4(),
						Port: addr.Port,
						Zone: addr.Zone,
					}
				}
				peer.Endpoint = addr.AddrPort()
			}
			if s.opts.ZoneAwarenessID != "" && desc.ZoneAwarenessID != "" {
				if desc.ZoneAwarenessID == s.opts.ZoneAwarenessID {
					if !localCIDRs.Contains(peer.Endpoint.Addr()) && len(desc.WireGuardEndpoints) > 0 {
						// We share zone awareness with the peer and their primary endpoint
						// is not in one of our local CIDRs. We'll try to use one of their
						// additional endpoints instead.
						for _, ep := range desc.WireGuardEndpoints {
							addr, err := net.ResolveUDPAddr("udp", ep)
							if err != nil {
								s.log.Error("could not resolve additional udp addr", slog.String("error", err.Error()))
								continue
							}
							if addr.AddrPort().Addr().Is4In6() {
								// Same as above, this is an IPv4 address masquerading as an IPv6 address.
								addr = &net.UDPAddr{
									IP:   addr.IP.To4(),
									Port: addr.Port,
									Zone: addr.Zone,
								}
							}
							ep := addr.AddrPort()
							if localCIDRs.Contains(ep.Addr()) {
								// We found an additional endpoint that is in one of our local
								// CIDRs. We'll use this one instead.
								peer.Endpoint = ep
								s.log.Info("zone awareness shared with peer, using LAN endpoint", slog.String("endpoint", peer.Endpoint.String()))
								break
							}
						}
					}
				}
			}
		}
		if desc.PrivateIPv4.IsValid() {
			peer.AllowedIPs = append(peer.AllowedIPs, desc.PrivateIPv4)
		}
		if desc.NetworkIPv6.IsValid() {
			peer.AllowedIPs = append(peer.AllowedIPs, desc.NetworkIPv6)
		}
		// Each descendant of our descendants is an allowed IP
		descTargets := adjacencyMap[edge.Target]
		if len(descTargets) > 0 {
			for descTarget := range descTargets {
				if _, ok := ourDescendants[descTarget]; !ok && descTarget != string(s.nodeID) {
					target, _ := graph.Vertex(descTarget)
					if target.PrivateIPv4.IsValid() {
						peer.AllowedIPs = append(peer.AllowedIPs, target.PrivateIPv4)
					}
					if target.NetworkIPv6.IsValid() {
						peer.AllowedIPs = append(peer.AllowedIPs, target.NetworkIPv6)
					}
				}
			}
		}
		slog.Debug("allowed ips for descendant",
			slog.Any("allowed_ips", peer.AllowedIPs), slog.String("descendant", desc.ID))
		if err := s.wg.PutPeer(context.Background(), peer); err != nil {
			return fmt.Errorf("put peer: %w", err)
		}
	}
	return nil
}
