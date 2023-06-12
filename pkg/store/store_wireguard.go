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
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/webmeshproj/node/pkg/meshdb/models/localdb"
	"github.com/webmeshproj/node/pkg/meshdb/peers"
	"github.com/webmeshproj/node/pkg/meshdb/state"
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
	}
	if s.opts.WireGuard.EndpointOverrides != "" {
		overrides, err := parseEndpointOverrides(s.opts.WireGuard.EndpointOverrides)
		if err != nil {
			return fmt.Errorf("parse endpoint overrides: %w", err)
		}
		wgopts.EndpointOverrides = overrides
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
	meshnetworkv6, err := state.New(s).GetULAPrefix(ctx)
	if err != nil {
		return fmt.Errorf("get ula prefix: %w", err)
	}
	self, err := peers.New(s).Get(ctx, string(s.nodeID))
	if err != nil {
		return fmt.Errorf("get self peer: %w", err)
	}
	key, err := localdb.New(s.localData).GetCurrentWireguardKey(ctx)
	if err != nil {
		return fmt.Errorf("get current wireguard key: %w", err)
	}
	wireguardKey, err := wgtypes.ParseKey(key.PrivateKey)
	if err != nil {
		return fmt.Errorf("parse wireguard key: %w", err)
	}
	err = s.configureWireguard(ctx, wireguardKey, self.PrivateIPv4, self.NetworkIPv6, meshnetworkv6)
	if err != nil {
		return fmt.Errorf("configure wireguard: %w", err)
	}
	return s.refreshWireguardPeers(ctx)
}

func (s *store) loadWireGuardKey(ctx context.Context) (wgtypes.Key, error) {
	var key wgtypes.Key
	keyData, err := localdb.New(s.LocalDB()).GetCurrentWireguardKey(ctx)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return key, fmt.Errorf("get current wireguard key: %w", err)
		}
		// We don't have a key yet, so we generate one.
		s.log.Info("generating wireguard key")
		key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return key, fmt.Errorf("generate wireguard key: %w", err)
		}
		// Save it to the database.
		params := localdb.SetCurrentWireguardKeyParams{
			PrivateKey: key.String(),
		}
		if s.opts.Mesh.KeyRotationInterval > 0 {
			params.ExpiresAt = sql.NullTime{
				Time:  time.Now().UTC().Add(s.opts.Mesh.KeyRotationInterval),
				Valid: true,
			}
		}
		s.log.Debug("saving wireguard key to database")
		if err = localdb.New(s.LocalDB()).SetCurrentWireguardKey(ctx, params); err != nil {
			return key, fmt.Errorf("set current wireguard key: %w", err)
		}
	} else if keyData.ExpiresAt.Valid && keyData.ExpiresAt.Time.Before(time.Now().UTC()) {
		// We have a key, but it's expired, so we generate a new one.
		s.log.Info("wireguard key expired, generating new one")
		key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return key, fmt.Errorf("generate wireguard key: %w", err)
		}
		// Save it to the database.
		params := localdb.SetCurrentWireguardKeyParams{
			PrivateKey: key.String(),
		}
		if s.opts.Mesh.KeyRotationInterval > 0 {
			params.ExpiresAt = sql.NullTime{
				Time:  time.Now().UTC().Add(s.opts.Mesh.KeyRotationInterval),
				Valid: true,
			}
		}
		if err = localdb.New(s.LocalDB()).SetCurrentWireguardKey(ctx, params); err != nil {
			return key, fmt.Errorf("set current wireguard key: %w", err)
		}
	} else {
		key, err = wgtypes.ParseKey(keyData.PrivateKey)
		if err != nil {
			return key, fmt.Errorf("parse wireguard key: %w", err)
		}
	}
	return key, nil
}

func (s *store) walkMeshDescendants(ctx context.Context) error {
	if s.wg == nil {
		return nil
	}

	s.wgmux.Lock()
	defer s.wgmux.Unlock()

	peers, err := mesh.WireGuardPeersFor(ctx, s, string(s.nodeID))
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
		// Resolve the endpoint and check for zone awareness
		if wgPeer.GetPrimaryEndpoint() != "" {
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
						Zone: addr.Zone,
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
