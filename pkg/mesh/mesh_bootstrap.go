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

package mesh

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/meshdb/networking"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	"github.com/webmeshproj/webmesh/pkg/meshdb/rbac"
	"github.com/webmeshproj/webmesh/pkg/meshdb/state"
	meshnet "github.com/webmeshproj/webmesh/pkg/net"
	"github.com/webmeshproj/webmesh/pkg/raft"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/util"
)

func (s *meshStore) bootstrap(ctx context.Context, features []v1.Feature) error {
	// Check if the mesh network is defined
	_, err := s.Storage().Get(ctx, state.IPv6PrefixKey)
	var firstBootstrap bool
	if err != nil {
		if !errors.Is(err, storage.ErrKeyNotFound) {
			return fmt.Errorf("get mesh network: %w", err)
		}
		firstBootstrap = true
	}
	if !firstBootstrap {
		// We have data, so the cluster is already bootstrapped.
		s.log.Info("cluster already bootstrapped, attempting to rejoin as voter")
		// We rejoin as a voter no matter what
		s.opts.Mesh.JoinAsVoter = true
		if len(s.opts.Bootstrap.Servers) == 0 {
			// We were the only bootstrap server, so we need to rejoin ourselves
			// This is not foolproof, but it's the best we can do if the bootstrap
			// flag is left on.
			s.log.Info("cluster already bootstrapped and no other servers set, attempting to rejoin self")
			return s.recoverWireguard(ctx)
		}
		// Try to rejoin one of the bootstrap servers
		return s.rejoinBootstrapServer(ctx, features)
	}
	if s.opts.Bootstrap.RestoreSnapshot != "" {
		s.log.Info("restoring snapshot from file", slog.String("file", s.opts.Bootstrap.RestoreSnapshot))
		f, err := os.Open(s.opts.Bootstrap.RestoreSnapshot)
		if err != nil {
			return fmt.Errorf("open snapshot file: %w", err)
		}
		defer f.Close()
		if err := s.raft.Restore(f); err != nil {
			return fmt.Errorf("restore snapshot: %w", err)
		}
		// We're done here, but restore procedure needs to be documented
		return s.recoverWireguard(ctx)
	}
	var bootstrapOpts raft.BootstrapOptions
	bootstrapOpts.Servers = s.opts.Bootstrap.Servers
	bootstrapOpts.AdvertiseAddress = s.opts.Bootstrap.AdvertiseAddress
	bootstrapOpts.OnBootstrapped = func(isLeader bool) error {
		if isLeader {
			return s.initialBootstrapLeader(ctx, features)
		}
		return s.initialBootstrapNonLeader(ctx, features)
	}
	err = s.raft.Bootstrap(ctx, &bootstrapOpts)
	if err != nil {
		// If the error is that we already bootstrapped and
		// there were other servers to bootstrap with, then
		// we might just need to rejoin the cluster.
		if errors.Is(err, raft.ErrAlreadyBootstrapped) {
			if len(s.opts.Bootstrap.Servers) > 0 {
				s.log.Info("cluster already bootstrapped, attempting to rejoin as voter")
				s.opts.Mesh.JoinAsVoter = true
				return s.rejoinBootstrapServer(ctx, features)
			}
			// We were the only bootstrap server, so we need to rejoin ourselves
			// This is not foolproof, but it's the best we can do if the bootstrap
			// flag is left on.
			s.log.Info("cluster already bootstrapped and no other servers set, attempting to rejoin self")
			return s.recoverWireguard(ctx)
		}
		return fmt.Errorf("bootstrap cluster: %w", err)
	}
	return nil
}

func (s *meshStore) initialBootstrapLeader(ctx context.Context, features []v1.Feature) error {
	cfg := s.raft.Configuration()

	// Set initial cluster configurations to the raft log
	meshnetworkv4, err := netip.ParsePrefix(s.opts.Bootstrap.IPv4Network)
	if err != nil {
		return fmt.Errorf("parse IPv4 network: %w", err)
	}
	meshnetworkv6, err := util.GenerateULA()
	if err != nil {
		return fmt.Errorf("generate ULA: %w", err)
	}
	s.log.Info("newly bootstrapped cluster, setting IPv4/IPv6 networks",
		slog.String("ipv4-network", s.opts.Bootstrap.IPv4Network),
		slog.String("ipv6-network", meshnetworkv6.String()))
	err = s.Storage().Put(ctx, state.IPv6PrefixKey, meshnetworkv6.String(), 0)
	if err != nil {
		return fmt.Errorf("set IPv6 prefix to db: %w", err)
	}
	err = s.Storage().Put(ctx, state.IPv4PrefixKey, meshnetworkv4.String(), 0)
	if err != nil {
		return fmt.Errorf("set IPv4 prefix to db: %w", err)
	}
	s.meshDomain = s.opts.Bootstrap.MeshDomain
	if !strings.HasSuffix(s.meshDomain, ".") {
		s.meshDomain += "."
	}
	err = s.Storage().Put(ctx, state.MeshDomainKey, s.meshDomain, 0)
	if err != nil {
		return fmt.Errorf("set mesh domain to db: %w", err)
	}

	// Initialize the RBAC system.
	rb := rbac.New(s.Storage())

	// Create an admin role and add the admin user/node to it.
	err = rb.PutRole(ctx, &v1.Role{
		Name: rbac.MeshAdminRole,
		Rules: []*v1.Rule{
			{
				Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_ALL},
				Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_ALL},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("create admin role: %w", err)
	}
	err = rb.PutRoleBinding(ctx, &v1.RoleBinding{
		Name: rbac.MeshAdminRole,
		Role: rbac.MeshAdminRoleBinding,
		Subjects: []*v1.Subject{
			{
				Name: s.opts.Bootstrap.Admin,
				Type: v1.SubjectType_SUBJECT_NODE,
			},
			{
				Name: s.opts.Bootstrap.Admin,
				Type: v1.SubjectType_SUBJECT_USER,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("create admin role binding: %w", err)
	}

	// Create a "voters" role and group then add ourselves and all the bootstrap servers
	// to it.
	err = rb.PutRole(ctx, &v1.Role{
		Name: rbac.VotersRole,
		Rules: []*v1.Rule{
			{
				Resources: []v1.RuleResource{v1.RuleResource_RESOURCE_VOTES},
				Verbs:     []v1.RuleVerb{v1.RuleVerb_VERB_PUT},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("create voters role: %w", err)
	}
	err = rb.PutGroup(ctx, &v1.Group{
		Name: rbac.VotersGroup,
		Subjects: func() []*v1.Subject {
			out := make([]*v1.Subject, 0)
			out = append(out, &v1.Subject{
				Type: v1.SubjectType_SUBJECT_NODE,
				Name: s.opts.Bootstrap.Admin,
			})
			for _, server := range cfg.Servers {
				out = append(out, &v1.Subject{
					Type: v1.SubjectType_SUBJECT_NODE,
					Name: string(server.ID),
				})
			}
			if s.opts.Bootstrap.Voters != "" {
				voters := strings.Split(s.opts.Bootstrap.Voters, ",")
				for _, voter := range voters {
					out = append(out, &v1.Subject{
						Type: v1.SubjectType_SUBJECT_NODE,
						Name: voter,
					})
				}
			}
			return out
		}(),
	})
	if err != nil {
		return fmt.Errorf("create voters group: %w", err)
	}
	err = rb.PutRoleBinding(ctx, &v1.RoleBinding{
		Name: rbac.BootstrapVotersRoleBinding,
		Role: rbac.VotersRole,
		Subjects: []*v1.Subject{
			{
				Type: v1.SubjectType_SUBJECT_GROUP,
				Name: rbac.VotersGroup,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("create voters role binding: %w", err)
	}

	// Initialize the Networking system.
	nw := networking.New(s.Storage())

	// Create a network ACL that ensures bootstrap servers and admins can continue to
	// communicate with each other.
	// TODO: This should be filtered to only apply to internal traffic.
	err = nw.PutNetworkACL(ctx, &v1.NetworkACL{
		Name:             networking.BootstrapNodesNetworkACLName,
		Priority:         math.MaxInt32,
		SourceNodes:      []string{"group:" + rbac.VotersGroup},
		DestinationNodes: []string{"group:" + rbac.VotersGroup},
		Action:           v1.ACLAction_ACTION_ACCEPT,
	})

	if err != nil {
		return fmt.Errorf("create bootstrap nodes network ACL: %w", err)
	}

	// Apply a default accept policy if configured
	if s.opts.Bootstrap.DefaultNetworkPolicy == string(NetworkPolicyAccept) {
		err = nw.PutNetworkACL(ctx, &v1.NetworkACL{
			Name:             "default-accept",
			Priority:         math.MinInt32,
			SourceNodes:      []string{"*"},
			DestinationNodes: []string{"*"},
			SourceCidrs:      []string{"*"},
			DestinationCidrs: []string{"*"},
			Action:           v1.ACLAction_ACTION_ACCEPT,
		})
		if err != nil {
			return fmt.Errorf("create default accept network ACL: %w", err)
		}
	}

	// If we have routes configured, add them to the db
	if len(s.opts.Mesh.Routes) > 0 {
		err = nw.PutRoute(ctx, &v1.Route{
			Name:             fmt.Sprintf("%s-auto", s.nodeID),
			Node:             s.ID(),
			DestinationCidrs: s.opts.Mesh.Routes,
		})
		if err != nil {
			return fmt.Errorf("create routes: %w", err)
		}
	}

	// We need to officially "join" ourselves to the cluster with a wireguard
	// address. This is done by creating a new node in the database and then
	// readding it to the cluster as a voter with the acquired address.
	s.log.Info("Registering ourselves as a node in the cluster", slog.String("server-id", s.ID()))
	p := peers.New(s.Storage())
	self := peers.Node{
		ID:                 s.ID(),
		GRPCPort:           s.opts.Mesh.GRPCAdvertisePort,
		RaftPort:           s.raft.ListenPort(),
		PrimaryEndpoint:    s.opts.Mesh.PrimaryEndpoint,
		WireGuardEndpoints: s.opts.WireGuard.Endpoints,
		ZoneAwarenessID:    s.opts.Mesh.ZoneAwarenessID,
		Features:           features,
	}
	// Go ahead and generate our private key.
	s.log.Info("Generating wireguard key for ourselves")
	wireguardKey, err := s.loadWireGuardKey(ctx)
	if err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}
	self.PublicKey = wireguardKey.PublicKey()
	// Allocate addresses
	var privatev4 netip.Prefix
	if !s.opts.Mesh.NoIPv4 {
		privatev4, err = s.plugins.AllocateIP(ctx, &v1.AllocateIPRequest{
			NodeId:  s.ID(),
			Subnet:  s.opts.Bootstrap.IPv4Network,
			Version: v1.AllocateIPRequest_IP_VERSION_4,
		})
		if err != nil {
			return fmt.Errorf("allocate IPv4 address: %w", err)
		}
		self.PrivateIPv4 = privatev4
	}
	// We always assign a v6 address, even if we're not using it.
	privatev6, err := s.plugins.AllocateIP(ctx, &v1.AllocateIPRequest{
		NodeId:  s.ID(),
		Subnet:  meshnetworkv6.String(),
		Version: v1.AllocateIPRequest_IP_VERSION_6,
	})
	if err != nil {
		return fmt.Errorf("allocate IPv4 address: %w", err)
	}
	self.PrivateIPv6 = privatev6
	s.log.Debug("Creating ourself in the database", slog.Any("params", self))
	err = p.Put(ctx, self)
	if err != nil {
		return fmt.Errorf("create node: %w", err)
	}
	// Pre-create slots and edges for the other bootstrap servers.
	for _, server := range cfg.Servers {
		if string(server.ID) == s.nodeID {
			continue
		}
		s.log.Info("creating node in database for bootstrap server",
			slog.String("server-id", string(server.ID)),
		)
		err = p.Put(ctx, peers.Node{
			ID: string(server.ID),
		})
		if err != nil {
			return fmt.Errorf("create node: %w", err)
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
	// If we have direct-peerings, add them to the db
	if len(s.opts.Mesh.DirectPeers) > 0 {
		for _, peer := range s.opts.Mesh.DirectPeers {
			err = p.Put(ctx, peers.Node{
				ID: peer,
			})
			if err != nil {
				return fmt.Errorf("create direct peerings: %w", err)
			}
			err = p.PutEdge(ctx, peers.Edge{
				From:   s.ID(),
				To:     peer,
				Weight: 0,
				Attrs: map[string]string{
					v1.EdgeAttributes_EDGE_ATTRIBUTE_ICE.String(): "true",
				},
			})
			if err != nil {
				return fmt.Errorf("create direct peerings: %w", err)
			}
		}
	}
	// Determine what our raft address will be
	var raftAddr string
	if !s.opts.Mesh.NoIPv4 && !s.opts.Raft.PreferIPv6 {
		raftAddr = net.JoinHostPort(privatev4.Addr().String(), strconv.Itoa(int(s.raft.ListenPort())))
	} else {
		raftAddr = net.JoinHostPort(privatev6.Addr().String(), strconv.Itoa(int(s.raft.ListenPort())))
	}
	if s.testStore {
		// We dont manage network connections on test stores
		return nil
	}
	// Start network resources
	s.log.Info("Starting network manager")
	opts := &meshnet.StartOptions{
		Key:       wireguardKey,
		AddressV4: privatev4,
		AddressV6: privatev6,
		NetworkV4: meshnetworkv4,
		NetworkV6: meshnetworkv6,
	}
	err = s.nw.Start(ctx, opts)
	if err != nil {
		return fmt.Errorf("start net manager: %w", err)
	}
	if s.opts.Mesh.UseMeshDNS && s.opts.Mesh.MeshDNSAdvertisePort != 0 {
		addr := "127.0.0.1"
		if s.opts.Mesh.NoIPv4 {
			addr = "::1"
		}
		addrport := netip.AddrPortFrom(netip.MustParseAddr(addr), uint16(s.opts.Mesh.MeshDNSAdvertisePort))
		err = s.nw.AddDNSServers(ctx, []netip.AddrPort{addrport})
		if err != nil {
			return fmt.Errorf("add dns servers: %w", err)
		}
	}
	// Make sure everyone is aware of the bootstrap data
	err = s.raft.Raft().Barrier(time.Second * 5).Error()
	if err != nil {
		return fmt.Errorf("barrier: %w", err)
	}
	// We need to readd ourselves server to the cluster as a voter with the acquired address.
	s.log.Info("re-adding ourselves to the cluster with the acquired wireguard address")
	err = s.raft.AddVoter(ctx, s.ID(), raftAddr)
	if err != nil {
		return fmt.Errorf("add voter: %w", err)
	}
	s.log.Info("initial bootstrap complete")
	return nil
}

func (s *meshStore) initialBootstrapNonLeader(ctx context.Context, features []v1.Feature) error {
	if s.testStore {
		return nil
	}
	// We "join" the cluster again through the usual workflow of adding a voter.
	leader, err := s.Leader()
	if err != nil {
		return fmt.Errorf("get leader ID: %w", err)
	}
	var advertiseAddress net.Addr
	for id, addr := range s.opts.Bootstrap.Servers {
		if id == leader {
			advertiseAddress, err = util.ResolveTCPAddr(ctx, addr, 10)
			if err != nil {
				return fmt.Errorf("resolve advertise address: %w", err)
			}
		}
	}
	// We need to extract the host part from the address
	// since we are going to use it to join the cluster.
	addr := advertiseAddress.(*net.TCPAddr).AddrPort()
	var grpcPort int
	if port, ok := s.opts.Bootstrap.ServersGRPCPorts[string(leader)]; ok {
		grpcPort = port
	} else {
		grpcPort = s.opts.Mesh.GRPCAdvertisePort
	}
	joinAddr := net.JoinHostPort(addr.Addr().String(), strconv.Itoa(grpcPort))
	s.opts.Mesh.JoinAsVoter = true
	time.Sleep(3 * time.Second)
	return s.join(ctx, features, joinAddr)
}

func (s *meshStore) rejoinBootstrapServer(ctx context.Context, features []v1.Feature) error {
	s.opts.Mesh.JoinAsVoter = true
	for id, server := range s.opts.Bootstrap.Servers {
		if id == s.ID() {
			continue
		}
		advertiseAddress, err := util.ResolveTCPAddr(ctx, server, 10)
		if err != nil {
			return fmt.Errorf("resolve advertise address: %w", err)
		}
		// We need to extract the host part from the address
		// since we are going to use it to join the cluster.
		addr := advertiseAddress.(*net.TCPAddr).AddrPort()
		var grpcPort int
		if port, ok := s.opts.Bootstrap.ServersGRPCPorts[id]; ok {
			grpcPort = port
		} else {
			grpcPort = s.opts.Mesh.GRPCAdvertisePort
		}
		joinAddr := net.JoinHostPort(addr.Addr().String(), strconv.Itoa(grpcPort))
		if err = s.join(ctx, features, joinAddr); err != nil {
			s.log.Warn("failed to rejoin bootstrap server", slog.String("error", err.Error()))
			continue
		}
		return nil
	}
	s.log.Error("no joinable bootstrap servers found, falling back to wireguard recovery")
	return s.recoverWireguard(ctx)
}
