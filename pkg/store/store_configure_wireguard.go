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
	"net/netip"

	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gitlab.com/webmesh/node/pkg/db/raftdb"
	"gitlab.com/webmesh/node/pkg/firewall"
	"gitlab.com/webmesh/node/pkg/wireguard"
)

func (s *store) ConfigureWireguard(ctx context.Context, key wgtypes.Key, networkv4, networkv6 netip.Prefix) error {
	s.wgmux.Lock()
	defer s.wgmux.Unlock()
	s.wgopts.NetworkV4 = networkv4
	s.wgopts.NetworkV6 = networkv6
	s.log.Info("configuring wireguard interface", slog.Any("options", s.wgopts))
	var err error
	if s.fw == nil {
		s.fw, err = firewall.New(&firewall.Options{
			DefaultPolicy: firewall.PolicyAccept,
			WireguardPort: uint16(s.wgopts.ListenPort),
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
	if networkv4.IsValid() {
		err = s.wg.AddRoute(ctx, networkv4)
		if err != nil && !wireguard.IsRouteExists(err) {
			return fmt.Errorf("wireguard add ipv4 route: %w", err)
		}
		s.wgroutes[networkv4] = struct{}{}
	}
	if networkv6.IsValid() {
		err = s.wg.AddRoute(ctx, networkv6)
		if err != nil && !wireguard.IsRouteExists(err) {
			return fmt.Errorf("wireguard add ipv6 route: %w", err)
		}
		s.wgroutes[networkv6] = struct{}{}
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

func (s *store) refreshWireguardPeers(ctx context.Context) error {
	if s.wg == nil {
		return nil
	}
	peers, err := raftdb.New(s.ReadDB()).ListNodePeers(ctx, string(s.nodeID))
	if err != nil {
		s.log.Error("list node peers", slog.String("error", err.Error()))
		return err
	}
	for _, peer := range peers {
		var privateIPv4 netip.Prefix
		var privateIPv6 netip.Prefix
		if peer.PrivateAddressV4 != "" && !s.opts.NoIPv4 {
			privateIPv4, err = netip.ParsePrefix(peer.PrivateAddressV4)
			if err != nil {
				s.log.Error("parse private ipv4", slog.String("error", err.Error()))
				return err
			}
		}
		if peer.NetworkIpv6.Valid && !s.opts.NoIPv6 {
			privateIPv6, err = netip.ParsePrefix(peer.NetworkIpv6.String)
			if err != nil {
				s.log.Error("parse private ipv6", slog.String("error", err.Error()))
				return err
			}
		}
		wgpeer := wireguard.Peer{
			ID:          peer.ID,
			PublicKey:   peer.PublicKey.String,
			Endpoint:    peer.Endpoint.String,
			PrivateIPv4: privateIPv4,
			PrivateIPv6: privateIPv6,
		}
		s.log.Debug("configuring wireguard peer", slog.Any("peer", wgpeer))
		if err := s.wg.PutPeer(ctx, &wgpeer); err != nil {
			s.log.Error("wireguard put peer", slog.String("error", err.Error()))
			return err
		}
	}
	return nil
}
