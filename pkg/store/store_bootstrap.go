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
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/webmeshproj/node/pkg/meshdb/models"
	"github.com/webmeshproj/node/pkg/meshdb/models/localdb"
	"github.com/webmeshproj/node/pkg/meshdb/models/raftdb"
	"github.com/webmeshproj/node/pkg/meshdb/peers"
	"github.com/webmeshproj/node/pkg/util"
)

func (s *store) bootstrap(ctx context.Context) error {
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
		if s.opts.BootstrapServers == "" {
			// We were the only bootstrap server
			s.log.Info("cluster already bootstrapped, rejoining as voter")
			// TODO: Configure wireguard and join the cluster
		}
		// Try to rejoin one of the bootstrap servers
		servers := strings.Split(s.opts.BootstrapServers, ",")
		for _, server := range servers {
			parts := strings.Split(server, "=")
			if len(parts) != 2 {
				return fmt.Errorf("invalid bootstrap server: %s", server)
			}
			if parts[0] == string(s.nodeID) {
				continue
			}
			addr, err := net.ResolveTCPAddr("tcp", parts[1])
			if err != nil {
				return fmt.Errorf("resolve advertise address: %w", err)
			}
			if err = s.join(ctx, addr.String()); err != nil {
				s.log.Warn("failed to rejoin bootstrap server", slog.String("error", err.Error()))
			}
			return nil
		}
		// We failed to rejoin any of the bootstrap servers
		return fmt.Errorf("failed to rejoin any bootstrap servers")
	}
	s.firstBootstrap = true
	if s.opts.AdvertiseAddress == "" && s.opts.BootstrapServers == "" {
		s.opts.AdvertiseAddress = fmt.Sprintf("localhost:%d", s.sl.ListenPort())
	} else if s.opts.AdvertiseAddress == "" {
		// Validate() doesn't allow this on the options
		// but lets go ahead and support it anyway.
		s.opts.AdvertiseAddress = s.opts.BootstrapServers
	}
	// There is a chance we are waiting for DNS to resolve.
	// Retry until the context is cancelled.
	var addr net.Addr
	for {
		addr, err = net.ResolveTCPAddr("tcp", s.opts.AdvertiseAddress)
		if err != nil {
			err = fmt.Errorf("resolve advertise address: %w", err)
			s.log.Error("failed to resolve advertise address", slog.String("error", err.Error()))
			select {
			case <-ctx.Done():
				return fmt.Errorf("%w: %w", err, ctx.Err())
			case <-time.After(time.Second * 2):
				continue
			}
		}
		break
	}
	cfg := raft.Configuration{
		Servers: []raft.Server{
			{
				Suffrage: raft.Voter,
				ID:       s.nodeID,
				Address:  raft.ServerAddress(addr.String()),
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
			// There is a chance we are waiting for DNS to resolve.
			// Retry until the context is cancelled.
			for {
				addr, err := net.ResolveTCPAddr("tcp", parts[1])
				if err != nil {
					err = fmt.Errorf("resolve advertise address: %w", err)
					s.log.Error("failed to resolve bootstrap server", slog.String("error", err.Error()))
					select {
					case <-ctx.Done():
						return fmt.Errorf("%w: %w", err, ctx.Err())
					case <-time.After(time.Second * 2):
						continue
					}
				}
				servers[raft.ServerID(parts[0])] = raft.ServerAddress(addr.String())
				break
			}
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
		deadline, ok := ctx.Deadline()
		var cancel context.CancelFunc
		if !ok {
			ctx, cancel = context.WithTimeout(context.Background(), s.opts.StartupTimeout)
		} else {
			ctx, cancel = context.WithDeadline(context.Background(), deadline)
		}
		defer cancel()
		defer close(s.readyErr)
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
	}()
	return nil
}

func (s *store) initialBootstrapLeader(ctx context.Context, grpcPorts map[raft.ServerID]int64) error {
	q := raftdb.New(s.DB())

	// Set initial cluster configurations to the raft log
	s.log.Info("newly bootstrapped cluster, setting IPv4/IPv6 networks",
		slog.String("ipv4-network", s.opts.BootstrapIPv4Network))
	ula, err := util.GenerateULA()
	if err != nil {
		return fmt.Errorf("generate ULA: %w", err)
	}
	s.log.Info("generated IPv6 ULA", slog.String("ula", ula.String()))
	err = q.SetULAPrefix(ctx, ula.String())
	if err != nil {
		return fmt.Errorf("set ULA prefix to db: %w", err)
	}
	err = q.SetIPv4Prefix(ctx, s.opts.BootstrapIPv4Network)
	if err != nil {
		return fmt.Errorf("set IPv4 prefix to db: %w", err)
	}

	if s.opts.BootstrapWithRaftACLs {
		s.log.Info("Bootstrapping with Raft ACLs enabled")
		// Write ACLs for all the bootstrap servers.
		cfg := s.raft.GetConfiguration().Configuration()
		var nodeIDs []string
		for _, server := range cfg.Servers {
			nodeIDs = append(nodeIDs, string(server.ID))
		}
		s.log.Info("writing bootstrap servers raft acl",
			slog.String("nodes", strings.Join(nodeIDs, ",")),
		)
		err = q.PutRaftACL(ctx, raftdb.PutRaftACLParams{
			Name:      "bootstrap-servers",
			Nodes:     strings.Join(nodeIDs, ","),
			Action:    int64(v1.ACLAction_ALLOW.Number()),
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		})
		if err != nil {
			return fmt.Errorf("put bootstrap servers raft acl: %w", err)
		}
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
	var endpoint string
	if s.opts.NodeEndpoint != "" {
		endpoint = s.opts.NodeEndpoint
	} else {
		// We will use the address of our advertise interface.
		listenAddr := s.sl.Addr()
		if listenAddr == nil {
			return fmt.Errorf("no advertise address available")
		}
		trimPort := strings.Split(listenAddr.String(), ":")[0]
		endpoint = trimPort
	}
	p := peers.New(s)
	params := &peers.PutOptions{
		ID:              string(s.nodeID),
		NetworkIPv6:     networkIPv6,
		GRPCPort:        s.opts.GRPCAdvertisePort,
		RaftPort:        s.sl.ListenPort(),
		PrimaryEndpoint: endpoint,
		ZoneAwarenessID: s.opts.ZoneAwarenessID,
	}
	if s.opts.NodeWireGuardEndpoints != "" {
		params.WireGuardEndpoints = strings.Split(s.opts.NodeWireGuardEndpoints, ",")
	}
	// Go ahead and generate our private key.
	s.log.Info("generating wireguard key for ourselves")
	wireguardKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}
	params.PublicKey = wireguardKey.PublicKey()
	s.log.Debug("creating node in database", slog.Any("params", params))
	_, err = p.Put(ctx, params)
	if err != nil {
		return fmt.Errorf("create node: %w", err)
	}
	s.log.Debug("saving wireguard key to database")
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
