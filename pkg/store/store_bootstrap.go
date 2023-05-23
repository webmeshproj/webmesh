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
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/hashicorp/raft"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gitlab.com/webmesh/node/pkg/db"
	"gitlab.com/webmesh/node/pkg/util"
)

func (s *store) bootstrap() error {
	ctx := context.TODO()
	version, err := db.GetDBVersion(s.data)
	if err != nil {
		return fmt.Errorf("get schema version: %w", err)
	}
	s.log.Info("current schema version", slog.Int("version", int(version)))
	if version != 0 {
		// We have a version, so the cluster is already bootstrapped.
		s.log.Info("cluster already bootstrapped, migrating schema to latest version")
		if err = db.Migrate(s.data); err != nil {
			return fmt.Errorf("db migrate: %w", err)
		}
		// We retrieve the last key we were using so we can re-establish raft communication.
		q := db.New(s.LocalDB())
		keyStr, err := q.GetCurrentWireguardKey(ctx)
		if err != nil {
			// TODO: This is a problem, but only if the bootstrap flag is left on for a long
			// time with no other voters available.
			return fmt.Errorf("get current wireguard key: %w", err)
		}
		key, err := wgtypes.ParseKey(keyStr)
		if err != nil {
			return fmt.Errorf("parse wireguard key: %w", err)
		}
		s.log.Info("configuring wireguard")
		thisPeer, err := db.New(s.WeakDB()).GetNode(ctx, string(s.nodeID))
		if err != nil {
			return fmt.Errorf("get this peer: %w", err)
		}
		// TODO: If our IPv4 lease expired we have no means of acquiring a new
		// one until the store is ready. This is a problem, but only if the bootstrap
		// flag is left on for a long time with no other voters available.
		var networkv6, networkv4 netip.Prefix
		if thisPeer.PrivateAddressV4 != "" && !s.opts.NoIPv4 {
			networkv4, err = netip.ParsePrefix(thisPeer.PrivateAddressV4)
			if err != nil {
				return fmt.Errorf("parse private address: %w", err)
			}
		}
		if thisPeer.NetworkIpv6.Valid && !s.opts.NoIPv6 {
			networkv6, err = netip.ParsePrefix(thisPeer.NetworkIpv6.String)
			if err != nil {
				return fmt.Errorf("parse private address: %w", err)
			}
		}
		if err := s.ConfigureWireguard(ctx, key, networkv4, networkv6); err != nil {
			return fmt.Errorf("configure wireguard: %w", err)
		}
		return nil
	}
	s.firstBootstrap = true
	cfg := raft.Configuration{
		Servers: []raft.Server{
			{
				Suffrage: raft.Voter,
				ID:       s.nodeID,
				Address:  raft.ServerAddress(s.opts.AdvertiseAddress),
			},
		},
	}
	future := s.raft.BootstrapCluster(cfg)
	if err := future.Error(); err != nil {
		return fmt.Errorf("bootstrap cluster: %w", err)
	}
	s.log.Info("migrating schema to latest version")
	if err = db.Migrate(s.data); err != nil {
		return fmt.Errorf("db migrate: %w", err)
	}
	go func() {
		defer close(s.readyErr)
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		if err := s.initialBootstrap(ctx); err != nil {
			s.log.Error("initial bootstrap failed", slog.String("error", err.Error()))
			s.readyErr <- err
		}
	}()
	return nil
}

func (s *store) initialBootstrap(ctx context.Context) error {
	<-s.ReadyNotify(ctx)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Make sure everything we do is committed to the log.
	q := db.New(s.DB())

	s.log.Info("newly bootstrapped cluster, setting IPv4/IPv6 networks",
		slog.String("ipv4-network", s.opts.BootstrapIPv4Network))
	ula, err := util.GenerateULA()
	if err != nil {
		return fmt.Errorf("generate ULA: %w", err)
	}
	s.log.Info("generated ULA", slog.String("ula", ula.String()))
	err = q.SetULAPrefix(ctx, ula.String())
	if err != nil {
		return fmt.Errorf("set ULA prefix to db: %w", err)
	}
	err = q.SetIPv4Prefix(ctx, s.opts.BootstrapIPv4Network)
	if err != nil {
		return fmt.Errorf("set IPv4 prefix to db: %w", err)
	}
	// We need to officially "join" ourselves to the cluster with a wireguard
	// address. This is done by creating a new node in the database and then
	// readding it to the cluster as a voter with the acquired address.
	s.log.Info("registering ourselves as a node in the cluster")
	networkIPv6, err := util.Random64(ula)
	if err != nil {
		return fmt.Errorf("generate random IPv6: %w", err)
	}
	var endpoint netip.AddrPort
	if s.wgopts.Endpoint != "" {
		endpoint, err = netip.ParseAddrPort(s.wgopts.Endpoint)
		if err != nil {
			return fmt.Errorf("parse endpoint: %w", err)
		}
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}
	params := db.CreateNodeParams{
		ID: string(s.nodeID),
		PublicKey: sql.NullString{
			String: key.PublicKey().String(),
			Valid:  true,
		},
		NetworkIpv6: sql.NullString{
			String: networkIPv6.String(),
			Valid:  true,
		},
		GrpcPort: int64(s.opts.GRPCAdvertisePort),
		RaftPort: int64(s.sl.ListenPort()),
	}
	if endpoint.IsValid() {
		params.Endpoint = sql.NullString{
			String: endpoint.String(),
			Valid:  true,
		}
	}
	_, err = q.CreateNode(ctx, params)
	if err != nil {
		return fmt.Errorf("create node: %w", err)
	}
	var networkv4 netip.Prefix
	var raftAddr string
	if !s.opts.NoIPv4 && !s.opts.RaftPreferIPv6 {
		// Grab the first IP address in the network
		networkcidrv4, err := netip.ParsePrefix(s.opts.BootstrapIPv4Network)
		if err != nil {
			return fmt.Errorf("parse IPv4 prefix: %w", err)
		}
		ip := networkcidrv4.Addr().Next()
		networkv4 = netip.PrefixFrom(ip, networkcidrv4.Bits())
		_, err = q.InsertNodeLease(ctx, db.InsertNodeLeaseParams{
			NodeID:    string(s.nodeID),
			Ipv4:      networkv4.String(),
			ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
		})
		if err != nil {
			return fmt.Errorf("insert node lease: %w", err)
		}
		s.log.Info("acquired IPv4 address", slog.String("address", networkv4.String()))
		raftAddr = net.JoinHostPort(networkv4.Addr().String(), strconv.Itoa(s.sl.ListenPort()))
	} else {
		raftAddr = net.JoinHostPort(networkIPv6.Addr().String(), strconv.Itoa(s.sl.ListenPort()))
	}
	// We need to readd ourselves to the cluster as a voter with the acquired addresses.
	s.log.Info("re-adding ourselves to the cluster with the acquired wireguard address")
	err = s.AddVoter(ctx, string(s.nodeID), raftAddr)
	if err != nil {
		return fmt.Errorf("add voter: %w", err)
	}
	s.log.Info("successfully readded ourselves to the cluster as a voter, configuring wireguard interface")
	err = s.ConfigureWireguard(ctx, key, networkv4, func() netip.Prefix {
		if s.opts.NoIPv6 {
			return netip.Prefix{}
		}
		return networkIPv6
	}())
	if err != nil {
		return fmt.Errorf("configure wireguard: %w", err)
	}
	s.log.Info("successfully configured wireguard interface, recording current key in case of future reboots")
	err = q.SetCurrentWireguardKey(ctx, key.String())
	if err != nil {
		return fmt.Errorf("set current wireguard key: %w", err)
	}
	return nil
}
