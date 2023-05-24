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
	"fmt"
	"net/netip"
	"time"

	v1 "gitlab.com/webmesh/api/v1"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"gitlab.com/webmesh/node/pkg/db/localdb"
	"gitlab.com/webmesh/node/pkg/wireguard"
)

func (s *store) join(ctx context.Context, joinAddr string) error {
	log := s.log.With(slog.String("join-addr", joinAddr))
	// Fetch the last key we used (TODO: make these rotatable)
	var key wgtypes.Key
	keyStr, err := localdb.New(s.LocalDB()).GetCurrentWireguardKey(ctx)
	if err != nil {
		if err != sql.ErrNoRows {
			return fmt.Errorf("get current wireguard key: %w", err)
		}
		// We don't have a key yet, so we generate one.
		log.Info("generating wireguard key")
		key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("generate wireguard key: %w", err)
		}
		// Save it to the database.
		if err = localdb.New(s.LocalDB()).SetCurrentWireguardKey(ctx, key.String()); err != nil {
			return fmt.Errorf("set current wireguard key: %w", err)
		}
	} else {
		key, err = wgtypes.ParseKey(keyStr)
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
			Id:             string(s.nodeID),
			PublicKey:      key.PublicKey().String(),
			RaftPort:       int32(s.sl.ListenPort()),
			GrpcPort:       int32(s.opts.GRPCAdvertisePort),
			WireguardPort:  int32(s.wgopts.ListenPort),
			Endpoint:       s.opts.NodeEndpoint,
			AssignIpv4:     !s.opts.NoIPv4,
			PreferRaftIpv6: s.opts.RaftPreferIPv6,
			AsVoter:        s.opts.JoinAsVoter,
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
	var networkv4, networkv6 netip.Prefix
	if resp.AddressIpv4 != "" && !s.opts.NoIPv4 {
		networkv4, err = netip.ParsePrefix(resp.AddressIpv4)
		if err != nil {
			return fmt.Errorf("parse ipv4 address: %w", err)
		}
	}
	if resp.NetworkIpv6 != "" && !s.opts.NoIPv6 {
		networkv6, err = netip.ParsePrefix(resp.NetworkIpv6)
		if err != nil {
			return fmt.Errorf("parse ipv6 address: %w", err)
		}
	}
	log.Info("configuring wireguard",
		slog.String("networkv4", networkv4.String()),
		slog.String("networkv6", networkv6.String()))
	err = s.ConfigureWireguard(ctx, key, networkv4, networkv6)
	if err != nil {
		return fmt.Errorf("configure wireguard: %w", err)
	}
	for _, peer := range resp.GetPeers() {
		wgpeer := wireguard.Peer{
			ID:        peer.GetId(),
			PublicKey: peer.GetPublicKey(),
			Endpoint:  peer.GetEndpoint(),
		}
		if peer.GetAddressIpv4() != "" && !s.opts.NoIPv4 {
			wgpeer.PrivateIPv4, err = netip.ParsePrefix(peer.GetAddressIpv4())
			if err != nil {
				return fmt.Errorf("parse ipv4 address: %w", err)
			}
		}
		if peer.GetAddressIpv6() != "" && !s.opts.NoIPv6 {
			wgpeer.PrivateIPv6, err = netip.ParsePrefix(peer.GetAddressIpv6())
			if err != nil {
				return fmt.Errorf("parse ipv6 network: %w", err)
			}
		}
		log.Info("adding wireguard peer", slog.Any("peer", wgpeer))
		err = s.wg.PutPeer(ctx, &wgpeer)
		if err != nil {
			return fmt.Errorf("add peer: %w", err)
		}
	}
	return nil
}
