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
	"github.com/webmeshproj/node/pkg/meshdb/rbac"
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
			// We were the only bootstrap server, so we need to rejoin ourselves
			// This is not foolproof, but it's the best we can do if the bootstrap
			// flag is left on.
			s.log.Info("cluster already bootstrapped, rejoining as voter")
			return s.recoverWireguard(ctx)
		}
		// Try to rejoin one of the bootstrap servers
		return s.rejoinBootstrapServer(ctx)
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
		// If the error is that we already bootstrapped and
		// there were other servers to bootstrap with, then
		// we might just need to rejoin the cluster.
		if errors.Is(err, raft.ErrCantBootstrap) && s.opts.BootstrapServers != "" {
			s.log.Info("cluster already bootstrapped, attempting to join as voter")
			s.log.Info("migrating raft schema to latest version")
			if err = models.MigrateRaftDB(s.weakData); err != nil {
				return fmt.Errorf("raft db migrate: %w", err)
			}
			if err = models.MigrateLocalDB(s.localData); err != nil {
				return fmt.Errorf("local db migrate: %w", err)
			}
			s.opts.JoinAsVoter = true
			return s.rejoinBootstrapServer(ctx)
		}
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
			err := s.initialBootstrapLeader(ctx)
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

func (s *store) initialBootstrapLeader(ctx context.Context) error {
	q := raftdb.New(s.DB())
	cfg := s.raft.GetConfiguration().Configuration()

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

	// Initialize the RBAC system.
	rb := rbac.New(s)

	// Create an admin role and add the admin user/node to it.
	err = rb.PutRole(ctx, &v1.Role{
		Name: "mesh-admin",
		Rules: []*v1.Rule{
			{
				Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_ALL},
				Verbs:     []v1.RuleVerbs{v1.RuleVerbs_VERB_ALL},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("create admin role: %w", err)
	}
	err = rb.PutRoleBinding(ctx, &v1.RoleBinding{
		Name: "mesh-admin",
		Role: "mesh-admin",
		Subjects: []*v1.Subject{
			{
				Name: s.opts.BootstrapAdmin,
				Type: v1.SubjectType_SUBJECT_NODE,
			},
			{
				Name: s.opts.BootstrapAdmin,
				Type: v1.SubjectType_SUBJECT_USER,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("create admin role binding: %w", err)
	}

	// Create a "voters" role and add ourselves and all the bootstrap servers
	// to it.
	err = rb.PutRole(ctx, &v1.Role{
		Name: "voters",
		Rules: []*v1.Rule{
			{
				Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_VOTES},
				Verbs:     []v1.RuleVerbs{v1.RuleVerbs_VERB_PUT},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("create voters role: %w", err)
	}
	roleBinding := &v1.RoleBinding{
		Name:     "bootstrap-voters",
		Role:     "voters",
		Subjects: make([]*v1.Subject, len(cfg.Servers)),
	}
	for i, server := range cfg.Servers {
		roleBinding.Subjects[i] = &v1.Subject{
			Type: v1.SubjectType_SUBJECT_NODE,
			Name: string(server.ID),
		}
	}
	err = rb.PutRoleBinding(ctx, roleBinding)
	if err != nil {
		return fmt.Errorf("create voters role binding: %w", err)
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
	p := peers.New(s)
	params := &peers.PutOptions{
		ID:              string(s.nodeID),
		NetworkIPv6:     networkIPv6,
		GRPCPort:        s.opts.GRPCAdvertisePort,
		RaftPort:        s.sl.ListenPort(),
		PrimaryEndpoint: s.opts.NodeEndpoint,
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
	// Pre-create slots and edges for the other bootstrap servers.
	for _, server := range cfg.Servers {
		if server.ID == s.nodeID {
			continue
		}
		s.log.Info("creating node in database for bootstrap server",
			slog.String("server-id", string(server.ID)),
		)
		// The server will generate and replace this when they join,
		// but the database will reject a non-unique key.
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("generate private key: %w", err)
		}
		// Generate an IPv6 address for the node.
		networkIPv6, err := util.Random64(ula)
		if err != nil {
			return fmt.Errorf("generate random IPv6: %w", err)
		}
		_, err = p.Put(ctx, &peers.PutOptions{
			ID:          string(server.ID),
			PublicKey:   key.PublicKey(),
			NetworkIPv6: networkIPv6,
		})
		if err != nil {
			return fmt.Errorf("create node: %w", err)
		}
		err = s.raft.Barrier(time.Second * 5).Error()
		if err != nil {
			return fmt.Errorf("barrier: %w", err)
		}
	}
	// Do the loop again for edges
	for _, server := range cfg.Servers {
		for _, peer := range cfg.Servers {
			if peer.ID == server.ID {
				continue
			}
			s.log.Info("creating edges in database for bootstrap server",
				slog.String("server-id", string(server.ID)),
				slog.String("peer-id", string(peer.ID)),
			)
			err = p.PutEdge(ctx, peers.Edge{
				From:   string(server.ID),
				To:     string(peer.ID),
				Weight: 99,
			})
			if err != nil {
				return fmt.Errorf("create edge: %w", err)
			}
			err = p.PutEdge(ctx, peers.Edge{
				From:   string(peer.ID),
				To:     string(server.ID),
				Weight: 99,
			})
			if err != nil {
				return fmt.Errorf("create edge: %w", err)
			}
		}
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
	var networkv6, meshnetworkv6 netip.Prefix
	if !s.opts.NoIPv6 {
		networkv6 = networkIPv6
		meshnetworkv6 = ula
	}
	if s.noWG {
		return nil
	}
	s.log.Info("configuring wireguard interface")
	err = s.configureWireguard(ctx, wireguardKey, networkv4, networkv6, meshnetworkv6)
	if err != nil {
		return fmt.Errorf("configure wireguard: %w", err)
	}
	// We need to readd ourselves server to the cluster as a voter with the acquired address.
	s.log.Info("re-adding ourselves to the cluster with the acquired wireguard address")
	err = s.AddVoter(ctx, string(s.nodeID), raftAddr)
	if err != nil {
		return fmt.Errorf("add voter: %w", err)
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
	// TODO: This creates a race condition where the leader might readd itself with
	// its wireguard address before we get here. We should instead match the leader
	// to their initial bootstrap address.
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
	s.opts.MaxJoinRetries = 5
	s.opts.JoinTimeout = 30 * time.Second
	s.opts.JoinAsVoter = true
	// TODO: Technically we want to wait for the first barrier to be reached before we
	//       start the join process. This is because we want to make sure that the
	//       leader has already written the first barrier to the log before we join.
	//       However, this is not possible right now because we don't have a way to
	//       wait for the first barrier to be reached.
	time.Sleep(3 * time.Second)
	return s.join(ctx, joinAddr)
}

func (s *store) rejoinBootstrapServer(ctx context.Context) error {
	servers := strings.Split(s.opts.BootstrapServers, ",")
	// Make sure we don't retry forever.
	s.opts.MaxJoinRetries = 5
	s.opts.JoinTimeout = 30 * time.Second
	s.opts.JoinAsVoter = true
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
			continue
		}
		return nil
	}
	s.log.Error("no joinable bootstrap servers found, falling back to wireguard recovery")
	return s.recoverWireguard(ctx)
}
