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
	"strconv"
	"strings"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/webmeshproj/webmesh/pkg/meshdb/networking"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	"github.com/webmeshproj/webmesh/pkg/meshdb/rbac"
	"github.com/webmeshproj/webmesh/pkg/meshdb/state"
	meshnet "github.com/webmeshproj/webmesh/pkg/net"
	"github.com/webmeshproj/webmesh/pkg/raft"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/util/netutil"
)

func (s *meshStore) bootstrap(ctx context.Context, opts ConnectOptions) error {
	// Check if the mesh network is defined
	s.log.Debug("Checking if cluster is already bootstrapped")
	_, err := s.Storage().GetValue(ctx, state.IPv6PrefixKey)
	var firstBootstrap bool
	if err != nil {
		if !storage.IsKeyNotFoundError(err) {
			return fmt.Errorf("get mesh network: %w", err)
		}
		firstBootstrap = true
	}
	// We will always attempt to rejoin as a voter
	opts.RequestVote = true
	if !firstBootstrap {
		// We have data, so the cluster is already bootstrapped.
		s.log.Info("Cluster already bootstrapped, attempting to rejoin as voter")
		return s.join(ctx, opts)
	}
	s.log.Debug("Cluster not yet bootstrapped, attempting to bootstrap")
	isLeader, joinRT, err := opts.Bootstrap.Transport.LeaderElect(ctx)
	if err != nil {
		if errors.Is(err, raft.ErrAlreadyBootstrapped) && joinRT != nil {
			s.log.Info("cluster already bootstrapped, attempting to rejoin as voter")
			opts.JoinRoundTripper = joinRT
			return s.join(ctx, opts)
		}
		return fmt.Errorf("leader elect: %w", err)
	}
	if isLeader {
		s.log.Info("We were elected leader")
		return s.initialBootstrapLeader(ctx, opts)
	}
	if s.testStore {
		return nil
	}
	s.log.Info("We were not elected leader")
	opts.JoinRoundTripper = joinRT
	return s.join(ctx, opts)
}

func (s *meshStore) initialBootstrapLeader(ctx context.Context, opts ConnectOptions) error {
	// We'll bootstrap the raft cluster as just ourselves.
	s.log.Info("Bootstrapping raft cluster")
	err := s.raft.Bootstrap(ctx)
	if err != nil {
		return fmt.Errorf("bootstrap raft: %w", err)
	}

	// Set initial cluster configurations to the raft log
	if opts.Bootstrap.IPv4Network == "" {
		opts.Bootstrap.IPv4Network = DefaultIPv4Network
	}
	if opts.Bootstrap.MeshDomain == "" {
		opts.Bootstrap.MeshDomain = DefaultMeshDomain
	}
	if opts.Bootstrap.Admin == "" {
		opts.Bootstrap.Admin = DefaultMeshAdmin
	}
	if opts.Bootstrap.DefaultNetworkPolicy == "" {
		opts.Bootstrap.DefaultNetworkPolicy = DefaultNetworkPolicy
	}
	meshnetworkv4, err := netip.ParsePrefix(opts.Bootstrap.IPv4Network)
	if err != nil {
		return fmt.Errorf("parse IPv4 network: %w", err)
	}
	meshnetworkv6, err := netutil.GenerateULA()
	if err != nil {
		return fmt.Errorf("generate ULA: %w", err)
	}
	s.log.Info("Newly bootstrapped cluster, setting IPv4/IPv6 networks",
		slog.String("ipv4-network", opts.Bootstrap.IPv4Network),
		slog.String("ipv6-network", meshnetworkv6.String()))
	err = s.Storage().PutValue(ctx, state.IPv6PrefixKey, meshnetworkv6.String(), 0)
	if err != nil {
		return fmt.Errorf("set IPv6 prefix to db: %w", err)
	}
	err = s.Storage().PutValue(ctx, state.IPv4PrefixKey, meshnetworkv4.String(), 0)
	if err != nil {
		return fmt.Errorf("set IPv4 prefix to db: %w", err)
	}
	s.meshDomain = opts.Bootstrap.MeshDomain
	if !strings.HasSuffix(s.meshDomain, ".") {
		s.meshDomain += "."
	}
	err = s.Storage().PutValue(ctx, state.MeshDomainKey, s.meshDomain, 0)
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
				Name: opts.Bootstrap.Admin,
				Type: v1.SubjectType_SUBJECT_NODE,
			},
			{
				Name: opts.Bootstrap.Admin,
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
				Name: opts.Bootstrap.Admin,
			})
			for _, id := range append(opts.Bootstrap.Servers, s.ID()) {
				out = append(out, &v1.Subject{
					Type: v1.SubjectType_SUBJECT_NODE,
					Name: string(id),
				})
			}
			if opts.Bootstrap.Voters != nil {
				for _, voter := range opts.Bootstrap.Voters {
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

	// We initialized rbac, but if the caller wants, we'll go ahead and disable it.
	if opts.Bootstrap.DisableRBAC {
		err = rb.Disable(ctx)
		if err != nil {
			return fmt.Errorf("disable rbac: %w", err)
		}
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
	if opts.Bootstrap.DefaultNetworkPolicy == "accept" {
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
	if len(opts.Routes) > 0 {
		err = nw.PutRoute(ctx, &v1.Route{
			Name: fmt.Sprintf("%s-auto", s.nodeID),
			Node: s.ID(),
			DestinationCidrs: func() []string {
				out := make([]string, 0)
				for _, r := range opts.Routes {
					out = append(out, r.String())
				}
				return out
			}(),
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
	pubKey := s.key.PublicKey()
	privatev6 := netutil.AssignToPrefix(meshnetworkv6, pubKey[:])
	self := peers.MeshNode{
		MeshNode: &v1.MeshNode{
			Id:              s.ID(),
			PrimaryEndpoint: opts.PrimaryEndpoint.String(),
			WireguardEndpoints: func() []string {
				out := make([]string, 0)
				for _, ep := range opts.WireGuardEndpoints {
					out = append(out, ep.String())
				}
				return out
			}(),
			ZoneAwarenessId: s.opts.ZoneAwarenessID,
			PublicKey:       pubKey.String(),
			PrivateIpv6:     privatev6.String(),
			Features:        opts.Features,
			JoinedAt:        timestamppb.New(time.Now().UTC()),
		},
	}
	// Allocate addresses
	var privatev4 netip.Prefix
	if !s.opts.DisableIPv4 {
		privatev4, err = s.plugins.AllocateIP(ctx, &v1.AllocateIPRequest{
			NodeId: s.ID(),
			Subnet: opts.Bootstrap.IPv4Network,
		})
		if err != nil {
			return fmt.Errorf("allocate IPv4 address: %w", err)
		}
		self.MeshNode.PrivateIpv4 = privatev4.String()
	}
	s.log.Debug("Creating ourself in the database", slog.Any("params", self))
	err = p.Put(ctx, self)
	if err != nil {
		return fmt.Errorf("create node: %w", err)
	}
	// Pre-create slots and edges for the other bootstrap servers.
	for _, id := range opts.Bootstrap.Servers {
		if id == s.nodeID {
			continue
		}
		s.log.Info("Creating node in database for bootstrap server",
			slog.String("server-id", id),
		)
		err = p.Put(ctx, peers.MeshNode{
			MeshNode: &v1.MeshNode{Id: id},
		})
		if err != nil {
			return fmt.Errorf("create node: %w", err)
		}
	}
	// Do the loop again for edges
	for _, id := range append(opts.Bootstrap.Servers, s.ID()) {
		for _, peer := range opts.Bootstrap.Servers {
			if id == peer {
				continue
			}
			s.log.Info("Creating edges in database for bootstrap server",
				slog.String("server-id", id),
				slog.String("peer-id", peer),
			)
			err = p.PutEdge(ctx, &v1.MeshEdge{
				Source: id,
				Target: peer,
				Weight: 99,
			})
			if err != nil {
				return fmt.Errorf("create edge: %w", err)
			}
			err = p.PutEdge(ctx, &v1.MeshEdge{
				Source: id,
				Target: peer,
				Weight: 99,
			})
			if err != nil {
				return fmt.Errorf("create edge: %w", err)
			}
		}
	}
	// If we have direct-peerings, add them to the db
	if len(opts.DirectPeers) > 0 {
		for peer, proto := range opts.DirectPeers {
			if peer == s.ID() {
				continue
			}
			err = p.Put(ctx, peers.MeshNode{
				MeshNode: &v1.MeshNode{Id: peer},
			})
			if err != nil {
				return fmt.Errorf("create direct peerings: %w", err)
			}
			err = p.PutEdge(ctx, &v1.MeshEdge{
				Source:     s.ID(),
				Target:     peer,
				Weight:     0,
				Attributes: peers.EdgeAttrsForProto(proto),
			})
			if err != nil {
				return fmt.Errorf("create direct peerings: %w", err)
			}
		}
	}
	if s.testStore {
		// We dont manage network connections on test stores
		return nil
	}
	// Determine what our raft address will be
	var raftAddr string
	if !s.opts.DisableIPv4 && !opts.PreferIPv6 {
		raftAddr = net.JoinHostPort(privatev4.Addr().String(), strconv.Itoa(int(s.raft.ListenPort())))
	} else {
		raftAddr = net.JoinHostPort(privatev6.Addr().String(), strconv.Itoa(int(s.raft.ListenPort())))
	}
	// Start network resources
	s.log.Info("Starting network manager")
	startopts := &meshnet.StartOptions{
		Key: s.key,
		AddressV4: func() netip.Prefix {
			if !s.opts.DisableIPv4 {
				return privatev4
			}
			return netip.Prefix{}
		}(),
		AddressV6: func() netip.Prefix {
			if !s.opts.DisableIPv6 {
				return privatev6
			}
			return netip.Prefix{}
		}(),
		NetworkV4: meshnetworkv4,
		NetworkV6: meshnetworkv6,
	}
	err = s.nw.Start(ctx, startopts)
	if err != nil {
		return fmt.Errorf("start net manager: %w", err)
	}
	if s.opts.UseMeshDNS && s.opts.LocalMeshDNSAddr != "" {
		addrport, err := netip.ParseAddrPort(s.opts.LocalMeshDNSAddr)
		if err != nil {
			return fmt.Errorf("parse local mesh dns addr: %w", err)
		}
		err = s.nw.DNS().AddServers(ctx, []netip.AddrPort{addrport})
		if err != nil {
			return fmt.Errorf("add dns servers: %w", err)
		}
	}
	// We need to readd ourselves server to the cluster as a voter with the acquired raft address.
	s.log.Info("Readmitting ourselves to the cluster with the acquired wireguard address")
	err = s.raft.AddVoter(ctx, s.ID(), raftAddr)
	if err != nil {
		return fmt.Errorf("add voter: %w", err)
	}
	s.log.Info("Initial network bootstrap complete")
	return nil
}
