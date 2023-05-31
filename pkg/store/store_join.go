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
	"strings"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/webmeshproj/node/pkg/meshdb/models/localdb"
	"github.com/webmeshproj/node/pkg/util"
	"github.com/webmeshproj/node/pkg/wireguard"
)

func (s *store) join(ctx context.Context, joinAddr string) error {
	log := s.log.With(slog.String("join-addr", joinAddr))
	var key wgtypes.Key
	keyData, err := localdb.New(s.LocalDB()).GetCurrentWireguardKey(ctx)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("get current wireguard key: %w", err)
		}
		// We don't have a key yet, so we generate one.
		log.Info("generating wireguard key")
		key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("generate wireguard key: %w", err)
		}
		// Save it to the database.
		params := localdb.SetCurrentWireguardKeyParams{
			PrivateKey: key.String(),
		}
		if s.opts.KeyRotationInterval > 0 {
			params.ExpiresAt = sql.NullTime{
				Time:  time.Now().UTC().Add(s.opts.KeyRotationInterval),
				Valid: true,
			}
		}
		if err = localdb.New(s.LocalDB()).SetCurrentWireguardKey(ctx, params); err != nil {
			return fmt.Errorf("set current wireguard key: %w", err)
		}
	} else if keyData.ExpiresAt.Valid && keyData.ExpiresAt.Time.Before(time.Now().UTC()) {
		// We have a key, but it's expired, so we generate a new one.
		log.Info("wireguard key expired, generating new one")
		key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("generate wireguard key: %w", err)
		}
		// Save it to the database.
		params := localdb.SetCurrentWireguardKeyParams{
			PrivateKey: key.String(),
		}
		if s.opts.KeyRotationInterval > 0 {
			params.ExpiresAt = sql.NullTime{
				Time:  time.Now().UTC().Add(s.opts.KeyRotationInterval),
				Valid: true,
			}
		}
		if err = localdb.New(s.LocalDB()).SetCurrentWireguardKey(ctx, params); err != nil {
			return fmt.Errorf("set current wireguard key: %w", err)
		}
	} else {
		key, err = wgtypes.ParseKey(keyData.PrivateKey)
		if err != nil {
			return fmt.Errorf("parse wireguard key: %w", err)
		}
	}
	log.Info("joining cluster")
	var creds credentials.TransportCredentials
	if tlsConfig := s.sl.TLSConfig(); tlsConfig != nil {
		creds = credentials.NewTLS(tlsConfig)
	} else {
		creds = insecure.NewCredentials()
	}
	var tries int
	var resp *v1.JoinResponse
	for tries <= s.opts.MaxJoinRetries {
		if tries > 0 {
			log.Info("retrying join request", slog.Int("tries", tries))
		}
		conn, err := grpc.DialContext(ctx, joinAddr, grpc.WithTransportCredentials(creds))
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			err = fmt.Errorf("dial join node: %w", err)
			log.Error("gRPC dial failed", slog.String("error", err.Error()))
			tries++
			time.Sleep(time.Second)
			continue
		}
		defer conn.Close()
		client := v1.NewNodeClient(conn)
		req := &v1.JoinRequest{
			Id:              string(s.nodeID),
			PublicKey:       key.PublicKey().String(),
			RaftPort:        int32(s.sl.ListenPort()),
			GrpcPort:        int32(s.opts.GRPCAdvertisePort),
			PrimaryEndpoint: s.opts.NodeEndpoint,
			WireguardEndpoints: func() []string {
				if s.opts.NodeWireGuardEndpoints != "" {
					return strings.Split(s.opts.NodeWireGuardEndpoints, ",")
				}
				return nil
			}(),
			ZoneAwarenessId: s.opts.ZoneAwarenessID,
			AssignIpv4:      !s.opts.NoIPv4,
			PreferRaftIpv6:  s.opts.RaftPreferIPv6,
			AsVoter:         s.opts.JoinAsVoter,
		}
		log.Info("sending join request to node", slog.Any("req", req))
		resp, err = client.Join(ctx, req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			err = fmt.Errorf("join node: %w", err)
			log.Error("join request failed", slog.String("error", err.Error()))
			tries++
			time.Sleep(time.Second)
			continue
		}
		break
	}
	if err != nil {
		return err
	}
	if resp == nil {
		return fmt.Errorf("join request failed")
	}
	log.Debug("received join response", slog.Any("resp", resp))
	var addressv4, addressv6, networkv6 netip.Prefix
	if resp.AddressIpv4 != "" && !s.opts.NoIPv4 {
		addressv4, err = netip.ParsePrefix(resp.AddressIpv4)
		if err != nil {
			return fmt.Errorf("parse ipv4 address: %w", err)
		}
	}
	if resp.AddressIpv6 != "" && !s.opts.NoIPv6 {
		addressv6, err = netip.ParsePrefix(resp.AddressIpv6)
		if err != nil {
			return fmt.Errorf("parse ipv6 address: %w", err)
		}
	}
	if !s.opts.NoIPv6 {
		networkv6, err = netip.ParsePrefix(resp.NetworkIpv6)
		if err != nil {
			return fmt.Errorf("parse ipv6 network: %w", err)
		}
	}
	log.Info("configuring wireguard",
		slog.String("networkv4", addressv4.String()),
		slog.String("networkv6", addressv6.String()))
	err = s.ConfigureWireguard(ctx, key, addressv4, addressv6, networkv6)
	if err != nil {
		return fmt.Errorf("configure wireguard: %w", err)
	}
	var localCIDRs util.PrefixList
	if s.opts.ZoneAwarenessID != "" {
		log.Info("using zone awareness, collecting local CIDRs")
		localCIDRs, err = util.DetectEndpoints(ctx, util.EndpointDetectOpts{
			DetectPrivate:  true,
			DetectIPv6:     !s.opts.NoIPv6,
			SkipInterfaces: []string{s.wg.Name()},
		})
		log.Debug("detected local CIDRs", slog.Any("cidrs", localCIDRs.Strings()))
		if err != nil {
			return fmt.Errorf("detect endpoints: %w", err)
		}
	}
	for _, peer := range resp.GetPeers() {
		key, err := wgtypes.ParseKey(peer.GetPublicKey())
		if err != nil {
			return fmt.Errorf("parse peer key: %w", err)
		}
		var endpoint netip.AddrPort
		addr, err := net.ResolveUDPAddr("udp", peer.GetPrimaryEndpoint())
		if err != nil {
			log.Error("could not resolve peer primary endpoint", slog.String("error", err.Error()))
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
			endpoint = addr.AddrPort()
		}
		if s.opts.ZoneAwarenessID != "" && peer.GetZoneAwarenessId() != "" {
			if peer.GetZoneAwarenessId() == s.opts.ZoneAwarenessID {
				if !localCIDRs.Contains(endpoint.Addr()) && len(peer.GetWireguardEndpoints()) > 0 {
					// We share zone awareness with the peer and their primary endpoint
					// is not in one of our local CIDRs. We'll try to use one of their
					// additional endpoints instead.
					for _, additionalEndpoint := range peer.GetWireguardEndpoints() {
						addr, err := net.ResolveUDPAddr("udp", additionalEndpoint)
						if err != nil {
							log.Error("could not resolve peer primary endpoint", slog.String("error", err.Error()))
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
							log.Info("zone awareness shared with peer, using LAN endpoint", slog.String("endpoint", ep.String()))
							endpoint = ep
							break
						}
					}
				}
			}
		}
		allowedIPs := make([]netip.Prefix, len(peer.GetAllowedIps()))
		for i, ip := range peer.GetAllowedIps() {
			allowedIPs[i], err = netip.ParsePrefix(ip)
			if err != nil {
				return fmt.Errorf("parse peer allowed ip: %w", err)
			}
		}
		wgpeer := wireguard.Peer{
			ID:         peer.GetId(),
			PublicKey:  key,
			Endpoint:   endpoint,
			AllowedIPs: allowedIPs,
		}
		log.Info("adding wireguard peer", slog.Any("peer", &wgpeer))
		err = s.wg.PutPeer(ctx, &wgpeer)
		if err != nil {
			return err
		}
	}
	return nil
}
