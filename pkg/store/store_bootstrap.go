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
	"strings"
	"time"

	"github.com/hashicorp/raft"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gitlab.com/webmesh/node/pkg/models"
	"gitlab.com/webmesh/node/pkg/models/localdb"
	"gitlab.com/webmesh/node/pkg/models/raftdb"
	"gitlab.com/webmesh/node/pkg/util"
)

func (s *store) bootstrap() error {
	ctx := context.TODO()
	version, err := models.GetDBVersion(s.weakData)
	if err != nil {
		return fmt.Errorf("get raft schema version: %w", err)
	}
	s.log.Info("current raft schema version", slog.Int("version", int(version)))
	if version != 0 {
		// We have a version, so the cluster is already bootstrapped.
		s.log.Info("cluster already bootstrapped, migrating schema to latest version")
		if err = models.MigrateRaftDB(s.weakData); err != nil {
			return fmt.Errorf("raft db migrate: %w", err)
		}
		if err = models.MigrateLocalDB(s.localData); err != nil {
			return fmt.Errorf("local db migrate: %w", err)
		}
		// We rejoin as a voter no matter what
		s.opts.JoinAsVoter = true
		// Pick an address to rejoin the cluster with.
		addrs, err := raftdb.New(s.ReadDB()).GetPeerPublicRPCAddresses(ctx, string(s.nodeID))
		if err != nil {
			return fmt.Errorf("get peer private rpc addresses: %w", err)
		}
		if len(addrs) == 0 {
			return fmt.Errorf("no private rpc addresses found")
		}
		return s.join(ctx, addrs[0].(string))
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
	if s.opts.BootstrapServers != "" {
		bootstrapServers := strings.Split(s.opts.BootstrapServers, ",")
		servers := make(map[raft.ServerID]raft.ServerAddress)
		for _, server := range bootstrapServers {
			parts := strings.Split(server, "=")
			if len(parts) != 2 {
				return fmt.Errorf("invalid bootstrap server: %s", server)
			}
			servers[raft.ServerID(parts[0])] = raft.ServerAddress(parts[1])
		}
		s.log.Info("bootstrapping from servers", slog.Any("servers", servers))
		for id, addr := range servers {
			if id != s.nodeID {
				cfg.Servers = append(cfg.Servers, raft.Server{
					Suffrage: raft.Voter,
					ID:       id,
					Address:  addr,
				})
			}
		}
	}
	future := s.raft.BootstrapCluster(cfg)
	if err := future.Error(); err != nil {
		return fmt.Errorf("bootstrap cluster: %w", err)
	}
	s.log.Info("migrating raft schema to latest version")
	if err = models.MigrateRaftDB(s.weakData); err != nil {
		return fmt.Errorf("raft db migrate: %w", err)
	}
	if err = models.MigrateLocalDB(s.localData); err != nil {
		return fmt.Errorf("local db migrate: %w", err)
	}
	go func() {
		defer close(s.readyErr)
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		s.log.Info("waiting for raft to become ready")
		<-s.ReadyNotify(ctx)
		if ctx.Err() != nil {
			s.readyErr <- ctx.Err()
			return
		}
		s.log.Info("raft is ready")
		grpcPorts := make(map[raft.ServerID]int64)
		if s.opts.BootstrapServersGRPCPorts != "" {
			ports := strings.Split(s.opts.BootstrapServersGRPCPorts, ",")
			for _, port := range ports {
				parts := strings.Split(port, "=")
				if len(parts) != 2 {
					s.readyErr <- fmt.Errorf("invalid bootstrap server grpc port: %s", port)
					return
				}
				p, err := strconv.ParseInt(parts[1], 10, 64)
				if err != nil {
					s.readyErr <- fmt.Errorf("invalid bootstrap server grpc port: %s", port)
					return
				}
				grpcPorts[raft.ServerID(parts[0])] = p
			}
		}
		if s.IsLeader() {
			err := s.initialBootstrapLeader(ctx, grpcPorts)
			if err != nil {
				s.log.Error("initial leader bootstrap failed", slog.String("error", err.Error()))
			}
			s.readyErr <- err
		} else {
			err := s.initialBootstrapNonLeader(ctx, grpcPorts)
			if err != nil {
				s.log.Error("initial non-leader bootstrap failed", slog.String("error", err.Error()))
			}
			s.readyErr <- err
		}
		// Do an initial refresh of the wireguard peers in a few seconds.
		go func() {
			time.Sleep(3 * time.Second)
			if err := s.RefreshWireguardPeers(context.Background()); err != nil {
				s.log.Error("refresh wireguard peers", slog.String("error", err.Error()))
			}
		}()
	}()
	return nil
}

func (s *store) initialBootstrapLeader(ctx context.Context, grpcPorts map[raft.ServerID]int64) error {
	q := raftdb.New(s.DB())

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
	s.log.Info("registering ourselves as a node in the cluster",
		slog.String("server-id", string(s.nodeID)))

	// Generate an IPv6 address for the node.
	networkIPv6, err := util.Random64(ula)
	if err != nil {
		return fmt.Errorf("generate random IPv6: %w", err)
	}
	var endpoint netip.Addr
	if s.opts.NodeEndpoint != "" {
		endpoint, err = netip.ParseAddr(s.opts.NodeEndpoint)
		if err != nil {
			return fmt.Errorf("parse node endpoint: %w", err)
		}
	} else {
		// We will use the address of our advertise interface.
		listenAddr := s.sl.Addr()
		if listenAddr == nil {
			return fmt.Errorf("no advertise address available")
		}
		listenEndpoint, err := netip.ParseAddrPort(listenAddr.String())
		if err != nil {
			return fmt.Errorf("parse listen address: %w", err)
		}
		endpoint = listenEndpoint.Addr()
	}
	params := raftdb.CreateNodeParams{
		ID: string(s.nodeID),
		NetworkIpv6: sql.NullString{
			String: networkIPv6.String(),
			Valid:  true,
		},
		GrpcPort:      int64(s.opts.GRPCAdvertisePort),
		RaftPort:      int64(s.sl.ListenPort()),
		WireguardPort: int64(s.wgopts.ListenPort),
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	// Go ahead and generate our private key.
	s.log.Info("generating wireguard key for ourselves")
	wireguardKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}
	keyparams := localdb.SetCurrentWireguardKeyParams{
		PrivateKey: wireguardKey.String(),
	}
	if s.opts.KeyRotationInterval > 0 {
		keyparams.ExpiresAt = sql.NullTime{
			Time:  time.Now().UTC().Add(s.opts.KeyRotationInterval),
			Valid: true,
		}
	}
	err = localdb.New(s.LocalDB()).SetCurrentWireguardKey(ctx, keyparams)
	if err != nil {
		return fmt.Errorf("set current wireguard key: %w", err)
	}
	params.PublicKey = sql.NullString{
		String: wireguardKey.PublicKey().String(),
		Valid:  true,
	}
	if endpoint.IsValid() {
		params.PrimaryEndpoint = sql.NullString{
			String: endpoint.String(),
			Valid:  true,
		}
	}
	if s.opts.NodeAdditionalEndpoints != "" {
		params.Endpoints = sql.NullString{
			String: s.opts.NodeAdditionalEndpoints,
			Valid:  true,
		}
	}
	s.log.Debug("creating node in database", slog.Any("params", params))
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
		networkv4 = netip.PrefixFrom(networkcidrv4.Addr().Next(), networkcidrv4.Bits())
		_, err = q.InsertNodeLease(ctx, raftdb.InsertNodeLeaseParams{
			NodeID: string(s.nodeID),
			Ipv4:   networkv4.String(),
		})
		if err != nil {
			return fmt.Errorf("insert node lease: %w", err)
		}
		s.log.Info("acquired IPv4 address for node",
			slog.String("server-id", string(s.nodeID)),
			slog.String("address", networkv4.String()))
		raftAddr = net.JoinHostPort(networkv4.Addr().String(), strconv.Itoa(int(s.sl.ListenPort())))
	} else {
		raftAddr = net.JoinHostPort(networkIPv6.Addr().String(), strconv.Itoa(int(s.sl.ListenPort())))
	}
	// We need to readd ourselves server to the cluster as a voter with the acquired address.
	s.log.Info("re-adding ourselves to the cluster with the acquired wireguard address")
	err = s.AddVoter(ctx, string(s.nodeID), raftAddr)
	if err != nil {
		return fmt.Errorf("add voter: %w", err)
	}
	s.log.Info("configuring wireguard interface")
	err = s.ConfigureWireguard(ctx, wireguardKey, networkv4, func() netip.Prefix {
		if s.opts.NoIPv6 {
			return netip.Prefix{}
		}
		return networkIPv6
	}())
	if err != nil {
		return fmt.Errorf("configure wireguard: %w", err)
	}
	s.log.Info("initial bootstrap complete")
	return nil
}

func (s *store) initialBootstrapNonLeader(ctx context.Context, grpcPorts map[raft.ServerID]int64) error {
	// We "join" the cluster again through the usual workflow of adding a voter.
	leader, err := s.Leader()
	if err != nil {
		return fmt.Errorf("get leader ID: %w", err)
	}
	config := s.raft.GetConfiguration().Configuration()
	var advertiseAddress netip.AddrPort
	for _, server := range config.Servers {
		if server.ID == leader {
			advertiseAddress, err = netip.ParseAddrPort(string(server.Address))
			if err != nil {
				return fmt.Errorf("parse advertise address: %w", err)
			}
			break
		}
	}
	if !advertiseAddress.IsValid() {
		return fmt.Errorf("leader %s not found in configuration", leader)
	}
	var grpcPort int64
	if port, ok := grpcPorts[raft.ServerID(leader)]; ok {
		grpcPort = port
	} else {
		grpcPort = int64(s.opts.GRPCAdvertisePort)
	}
	joinAddr := net.JoinHostPort(advertiseAddress.Addr().String(), strconv.Itoa(int(grpcPort)))
	s.opts.JoinAsVoter = true
	return s.join(ctx, joinAddr)
}
