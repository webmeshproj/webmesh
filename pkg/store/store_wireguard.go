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

package store

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/meshdb/peers"
	"github.com/webmeshproj/node/pkg/meshdb/state"
	"github.com/webmeshproj/node/pkg/net/datachannels"
	"github.com/webmeshproj/node/pkg/net/firewall"
	"github.com/webmeshproj/node/pkg/net/mesh"
	"github.com/webmeshproj/node/pkg/net/system"
	"github.com/webmeshproj/node/pkg/net/wireguard"
	"github.com/webmeshproj/node/pkg/util"
)

func (s *store) configureWireguard(ctx context.Context, key wgtypes.Key, addressv4, addressv6, meshNetworkV6 netip.Prefix) error {
	s.wgmux.Lock()
	defer s.wgmux.Unlock()
	wgopts := wireguard.Options{
		NodeID:              s.ID(),
		ListenPort:          s.opts.WireGuard.ListenPort,
		Name:                s.opts.WireGuard.InterfaceName,
		ForceName:           s.opts.WireGuard.ForceInterfaceName,
		ForceTUN:            s.opts.WireGuard.ForceTUN,
		Modprobe:            s.opts.WireGuard.Modprobe,
		PersistentKeepAlive: s.opts.WireGuard.PersistentKeepAlive,
		EndpointOverrides:   map[string]netip.AddrPort{},
		MTU:                 s.opts.WireGuard.MTU,
		NetworkV4:           addressv4,
		NetworkV6:           addressv6,
		IsPublic:            s.opts.Mesh.PrimaryEndpoint != "",
		Metrics:             s.opts.WireGuard.RecordMetrics,
		MetricsInterval:     s.opts.WireGuard.RecordMetricsInterval,
	}
	s.log.Info("configuring wireguard interface", slog.Any("options", &wgopts))
	var err error
	if s.fw == nil {
		s.fw, err = firewall.New(&firewall.Options{
			DefaultPolicy: firewall.PolicyAccept,
			WireguardPort: uint16(s.opts.WireGuard.ListenPort),
			RaftPort:      uint16(s.sl.ListenPort()),
			GRPCPort:      uint16(s.opts.Mesh.GRPCPort),
		})
		if err != nil {
			return fmt.Errorf("new firewall: %w", err)
		}
	}
	if s.wg == nil {
		s.wg, err = wireguard.New(ctx, &wgopts)
		if err != nil {
			return fmt.Errorf("new wireguard: %w", err)
		}
		err = s.wg.Up(ctx)
		if err != nil {
			return fmt.Errorf("wireguard up: %w", err)
		}
	}
	err = s.wg.Configure(ctx, key, s.opts.WireGuard.ListenPort)
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
	if s.opts.WireGuard.Masquerade || len(s.opts.Mesh.Routes) > 0 {
		err = s.fw.AddMasquerade(ctx, s.wg.Name())
		if err != nil {
			return fmt.Errorf("failed to add masquerade rule: %w", err)
		}
		s.masquerading = true
	}
	return nil
}

func (s *store) refreshWireguardPeers(ctx context.Context) error {
	if s.wg == nil {
		return nil
	}
	err := s.walkMeshDescendants(ctx)
	if err != nil {
		s.log.Error("walk mesh descendants", slog.String("error", err.Error()))
		return nil
	}
	return nil
}

func (s *store) recoverWireguard(ctx context.Context) error {
	if s.noWG {
		return nil
	}
	var meshnetworkv6 netip.Prefix
	var err error
	if !s.opts.Mesh.NoIPv6 {
		meshnetworkv6, err = state.New(s.DB()).GetULAPrefix(ctx)
		if err != nil {
			return fmt.Errorf("get ula prefix: %w", err)
		}
	}
	p := peers.New(s.DB())
	self, err := p.Get(ctx, s.ID())
	if err != nil {
		return fmt.Errorf("get self peer: %w", err)
	}
	wireguardKey, err := s.loadWireGuardKey(ctx)
	if err != nil {
		return fmt.Errorf("get current wireguard key: %w", err)
	}
	err = s.configureWireguard(ctx, wireguardKey, func() netip.Prefix {
		if s.opts.Mesh.NoIPv4 {
			return netip.Prefix{}
		}
		return self.PrivateIPv4
	}(), func() netip.Prefix {
		if s.opts.Mesh.NoIPv6 {
			return netip.Prefix{}
		}
		return self.NetworkIPv6
	}(), meshnetworkv6)
	if err != nil {
		return fmt.Errorf("configure wireguard: %w", err)
	}
	return s.refreshWireguardPeers(ctx)
}

func (s *store) walkMeshDescendants(ctx context.Context) error {
	if s.wg == nil {
		return nil
	}

	s.wgmux.Lock()
	defer s.wgmux.Unlock()

	peers, err := mesh.WireGuardPeersFor(ctx, s, s.ID())
	if err != nil {
		return fmt.Errorf("wireguard peers for: %w", err)
	}
	s.log.Debug("current wireguard peers", slog.Any("peers", peers))

	currentPeers := s.wg.Peers()
	seenPeers := make(map[string]struct{})

	var localCIDRs util.PrefixList
	if s.opts.Mesh.ZoneAwarenessID != "" {
		s.log.Debug("using zone awareness, collecting local CIDRs")
		localCIDRs, err = util.DetectEndpoints(context.Background(), util.EndpointDetectOpts{
			DetectPrivate:  true,
			DetectIPv6:     !s.opts.Mesh.NoIPv6,
			SkipInterfaces: []string{s.wg.Name()},
		})
		s.log.Debug("detected local CIDRs", slog.Any("cidrs", localCIDRs.Strings()))
		if err != nil {
			return fmt.Errorf("detect endpoints: %w", err)
		}
	}
	for _, wgPeer := range peers {
		key, err := wgtypes.ParseKey(wgPeer.GetPublicKey())
		if err != nil {
			return fmt.Errorf("parse wireguard key: %w", err)
		}
		peer := &wireguard.Peer{
			ID:            wgPeer.GetId(),
			PublicKey:     key,
			AllowedIPs:    make([]netip.Prefix, len(wgPeer.GetAllowedIps())),
			AllowedRoutes: make([]netip.Prefix, len(wgPeer.GetAllowedRoutes())),
		}
		for i, ip := range wgPeer.GetAllowedIps() {
			peer.AllowedIPs[i], err = netip.ParsePrefix(ip)
			if err != nil {
				return fmt.Errorf("parse prefix: %w", err)
			}
		}
		for i, ip := range wgPeer.GetAllowedRoutes() {
			peer.AllowedRoutes[i], err = netip.ParsePrefix(ip)
			if err != nil {
				return fmt.Errorf("parse peer allowed route: %w", err)
			}
		}
		if wgPeer.GetIce() {
			// We are using ICE with this peer.
			// If we are already peered with this peer, we don't need to do anything.
			// Otherwise, we need to negotiate a new connection.
			if conn, ok := s.peerConns[peer.ID]; ok {
				peer.Endpoint = conn.localAddr.AddrPort()
			} else {
				// We need to negotiate a new connection.
				iceAddrs, err := state.New(s.DB()).ListPublicPeersWithFeature(ctx, s.grpcCreds(ctx), s.ID(), v1.Feature_ICE_NEGOTIATION)
				if err != nil {
					// DB error, somethings wrong, bail.
					return fmt.Errorf("list public peers with feature: %w", err)
				}
				// Pick the first address that is not the peer we are trying to connect to.
				var iceAddr netip.AddrPort
				for node, addr := range iceAddrs {
					if node != peer.ID {
						iceAddr = addr
						break
					}
				}
				// If any of these fail, there is still a chance the peer will be able to connect to us.
				if !iceAddr.IsValid() {
					s.log.Error("no ice addresses found, cannot connect to peer directly", slog.String("peer", peer.ID))
				} else {
					l, err := s.negotiateWireGuardICEConnection(ctx, iceAddr.String(), wgPeer)
					if err != nil {
						s.log.Error("could not negotiate ice connection, cannot connect to peer directly", slog.String("peer", peer.ID), slog.String("error", err.Error()))
					} else {
						peer.Endpoint = l.AddrPort()
					}
				}
			}
		} else if wgPeer.GetPrimaryEndpoint() != "" {
			// Resolve the endpoint and check for zone awareness
			addr, err := net.ResolveUDPAddr("udp", wgPeer.GetPrimaryEndpoint())
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
					}
				}
				peer.Endpoint = addr.AddrPort()
			}
			if s.opts.Mesh.ZoneAwarenessID != "" && wgPeer.GetZoneAwarenessId() != "" {
				if wgPeer.GetZoneAwarenessId() == s.opts.Mesh.ZoneAwarenessID {
					if !localCIDRs.Contains(peer.Endpoint.Addr()) && len(wgPeer.GetWireguardEndpoints()) > 0 {
						// We share zone awareness with the peer and their primary endpoint
						// is not in one of our local CIDRs. We'll try to use one of their
						// additional endpoints instead.
						for _, ep := range wgPeer.GetWireguardEndpoints() {
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
		if err := s.wg.PutPeer(ctx, peer); err != nil {
			return fmt.Errorf("put peer: %w", err)
		}
		seenPeers[peer.ID] = struct{}{}
	}
	// Remove any peers that are no longer in the DAG
	for _, peer := range currentPeers {
		if _, ok := seenPeers[peer]; !ok {
			s.log.Info("removing peer", slog.String("peer_id", peer))
			if err := s.wg.DeletePeer(ctx, peer); err != nil {
				return fmt.Errorf("delete peer: %w", err)
			}
		}
	}
	return nil
}

func (s *store) loadWireGuardKey(ctx context.Context) (wgtypes.Key, error) {
	var key wgtypes.Key
	var err error
	if s.opts.WireGuard.KeyFile != "" {
		// Load the key from the specified file.
		stat, err := os.Stat(s.opts.WireGuard.KeyFile)
		if err != nil && !os.IsNotExist(err) {
			return key, fmt.Errorf("stat key file: %w", err)
		}
		if err == nil {
			if stat.IsDir() {
				return key, fmt.Errorf("key file is a directory")
			}
			if stat.ModTime().Add(s.opts.WireGuard.KeyRotationInterval).Before(time.Now()) {
				// Delete the key file if it's older than the key rotation interval.
				s.log.Info("removing expired wireguard key file")
				if err := os.Remove(s.opts.WireGuard.KeyFile); err != nil {
					return key, fmt.Errorf("remove key file: %w", err)
				}
			} else {
				// If we got here, the key file exists and is not older than the key rotation interval.
				// We'll load the key from the file.
				s.log.Info("loading wireguard key from file")
				keyData, err := os.ReadFile(s.opts.WireGuard.KeyFile)
				if err != nil {
					return key, fmt.Errorf("read key file: %w", err)
				}
				return wgtypes.ParseKey(strings.TrimSpace(string(keyData)))
			}
		}
	}
	s.log.Info("generating new wireguard key")
	// Generate a new key and save it to the specified file.
	key, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		return key, fmt.Errorf("generate private key: %w", err)
	}
	if s.opts.WireGuard.KeyFile != "" {
		if err := os.WriteFile(s.opts.WireGuard.KeyFile, []byte(key.String()+"\n"), 0600); err != nil {
			return key, fmt.Errorf("write key file: %w", err)
		}
	}
	return key, nil
}

func (s *store) negotiateWireGuardICEConnection(ctx context.Context, server string, peer *v1.WireGuardPeer) (*net.UDPAddr, error) {
	s.pcmux.Lock()
	defer s.pcmux.Unlock()

	log := context.LoggerFrom(ctx)
	log.Info("negotiating wireguard ICE connection", slog.String("server", server), slog.String("peer", peer.GetId()))
	conn, err := s.newGRPCConn(ctx, server)
	if err != nil {
		return nil, fmt.Errorf("dial webRTC server: %w", err)
	}
	defer conn.Close()
	pc, err := datachannels.NewClientPeerConnection(ctx, &datachannels.ClientOptions{
		Client:      v1.NewWebRTCClient(conn),
		NodeID:      peer.GetId(),
		Protocol:    "udp",
		Destination: "127.0.0.1",
		Port:        0,
	})
	if err != nil {
		return nil, fmt.Errorf("create peer connection: %w", err)
	}
	select {
	case <-ctx.Done():
		defer pc.Close()
		return nil, ctx.Err()
	case err := <-pc.Errors():
		defer pc.Close()
		return nil, fmt.Errorf("peer connection error: %w", err)
	case <-pc.Closed():
		return nil, fmt.Errorf("peer connection failed to become ready")
	case <-pc.Ready():
		log.Info("wireguard ICE connection ready", slog.String("peer", peer.GetId()))
	}
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 0})
	if err != nil {
		defer pc.Close()
		return nil, fmt.Errorf("listen: %w", err)
	}
	localAddr := l.LocalAddr().(*net.UDPAddr)
	if localAddr.AddrPort().Addr().Is4In6() {
		// This is an IPv4 address masquerading as an IPv6 address.
		// We need to convert it to a real IPv4 address.
		// This is a workaround for a bug in Go's net package.
		localAddr = &net.UDPAddr{
			IP:   localAddr.IP.To4(),
			Port: localAddr.Port,
		}
	}
	go func() {
		// TODO: reopen the connection if it closes and we are still
		// peered with the node.
		defer pc.Close()
		pc.Handle(l)
		s.pcmux.Lock()
		defer s.pcmux.Unlock()
		delete(s.peerConns, peer.GetId())
	}()
	s.peerConns[peer.GetId()] = clientPeerConn{
		peerConn:  pc,
		localAddr: localAddr,
	}
	return localAddr, nil
}
