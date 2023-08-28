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

	v1 "github.com/webmeshproj/api/v1"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/webmeshproj/webmesh/pkg/meshdb/networking"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	"github.com/webmeshproj/webmesh/pkg/meshdb/rbac"
	"github.com/webmeshproj/webmesh/pkg/meshdb/state"
	meshnet "github.com/webmeshproj/webmesh/pkg/net"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/raft"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/util/netutil"
)

type MeshBootstrapOptions struct {
	// BootstrapTransport is the transport to use for bootstrapping.
	BootstrapTransport transport.BootstrapTransport
	// WireguardKey is the wireguard key to use for bootstrapping.
	WireguardKey wgtypes.Key
	// JoinRoundTripper is the round tripper to use for joining if
	// we detect we are already bootstrapped.
	JoinRoundTripper transport.JoinRoundTripper
	// Features are the features to advertise when bootstrapping.
	Features []v1.Feature
}

func (s *meshStore) bootstrap(ctx context.Context, opts MeshBootstrapOptions) error {
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
	s.opts.Mesh.JoinAsVoter = true
	if !firstBootstrap {
		// We have data, so the cluster is already bootstrapped.
		s.log.Info("Cluster already bootstrapped, attempting to rejoin as voter")
		return s.join(ctx, opts.JoinRoundTripper, opts.Features, opts.WireguardKey)
	}
	s.log.Debug("Cluster not yet bootstrapped, attempting to bootstrap")
	isLeader, joinRT, err := opts.BootstrapTransport.LeaderElect(ctx)
	if err != nil {
		if errors.Is(err, raft.ErrAlreadyBootstrapped) && len(s.opts.Bootstrap.Servers) > 0 {
			s.log.Info("cluster already bootstrapped, attempting to rejoin as voter")
			return s.join(ctx, opts.JoinRoundTripper, opts.Features, opts.WireguardKey)
		}
		return fmt.Errorf("leader elect: %w", err)
	}
	if isLeader {
		s.log.Info("We were elected leader")
		return s.initialBootstrapLeader(ctx, opts.Features, opts.WireguardKey)
	}
	if s.testStore {
		return nil
	}
	s.log.Info("We were not elected leader")
	return s.join(ctx, joinRT, opts.Features, opts.WireguardKey)
}

func (s *meshStore) initialBootstrapLeader(ctx context.Context, features []v1.Feature, wireguardKey wgtypes.Key) error {
	// We'll bootstrap the raft cluster as just ourselves.
	s.log.Info("Bootstrapping raft cluster")
	err := s.raft.Bootstrap(ctx)
	if err != nil {
		return fmt.Errorf("bootstrap raft: %w", err)
	}

	// Set initial cluster configurations to the raft log
	meshnetworkv4, err := netip.ParsePrefix(s.opts.Bootstrap.IPv4Network)
	if err != nil {
		return fmt.Errorf("parse IPv4 network: %w", err)
	}
	meshnetworkv6, err := netutil.GenerateULA()
	if err != nil {
		return fmt.Errorf("generate ULA: %w", err)
	}
	s.log.Info("newly bootstrapped cluster, setting IPv4/IPv6 networks",
		slog.String("ipv4-network", s.opts.Bootstrap.IPv4Network),
		slog.String("ipv6-network", meshnetworkv6.String()))
	err = s.Storage().PutValue(ctx, state.IPv6PrefixKey, meshnetworkv6.String(), 0)
	if err != nil {
		return fmt.Errorf("set IPv6 prefix to db: %w", err)
	}
	err = s.Storage().PutValue(ctx, state.IPv4PrefixKey, meshnetworkv4.String(), 0)
	if err != nil {
		return fmt.Errorf("set IPv4 prefix to db: %w", err)
	}
	s.meshDomain = s.opts.Bootstrap.MeshDomain
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
			for id := range s.opts.Bootstrap.Servers {
				out = append(out, &v1.Subject{
					Type: v1.SubjectType_SUBJECT_NODE,
					Name: string(id),
				})
			}
			if s.opts.Bootstrap.Voters != nil {
				for _, voter := range s.opts.Bootstrap.Voters {
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
	if s.opts.Bootstrap.DisableRBAC {
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
	pubKey := wireguardKey.PublicKey()
	self := peers.Node{
		ID:                 s.ID(),
		PublicKey:          wireguardKey.PublicKey(),
		PrivateIPv6:        netutil.AssignToPrefix(meshnetworkv6, pubKey[:]),
		GRPCPort:           s.opts.Mesh.GRPCAdvertisePort,
		RaftPort:           int(s.raft.ListenPort()),
		PrimaryEndpoint:    s.opts.Mesh.PrimaryEndpoint,
		WireGuardEndpoints: s.opts.WireGuard.Endpoints,
		ZoneAwarenessID:    s.opts.Mesh.ZoneAwarenessID,
		Features:           features,
	}
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
	s.log.Debug("Creating ourself in the database", slog.Any("params", self))
	err = p.Put(ctx, self)
	if err != nil {
		return fmt.Errorf("create node: %w", err)
	}
	// Pre-create slots and edges for the other bootstrap servers.
	for id := range s.opts.Bootstrap.Servers {
		if id == s.nodeID {
			continue
		}
		s.log.Info("creating node in database for bootstrap server",
			slog.String("server-id", id),
		)
		err = p.Put(ctx, peers.Node{
			ID: id,
		})
		if err != nil {
			return fmt.Errorf("create node: %w", err)
		}
	}
	// Do the loop again for edges
	for id := range s.opts.Bootstrap.Servers {
		for _, peer := range s.opts.Bootstrap.Servers {
			if id == peer {
				continue
			}
			s.log.Info("creating edges in database for bootstrap server",
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
	if len(s.opts.Mesh.DirectPeers) > 0 {
		for _, peer := range s.opts.Mesh.DirectPeers {
			if peer == s.ID() {
				continue
			}
			err = p.Put(ctx, peers.Node{
				ID: peer,
			})
			if err != nil {
				return fmt.Errorf("create direct peerings: %w", err)
			}
			err = p.PutEdge(ctx, &v1.MeshEdge{
				Source: s.ID(),
				Target: peer,
				Weight: 0,
				Attributes: map[string]string{
					v1.EdgeAttributes_EDGE_ATTRIBUTE_ICE.String(): "true",
				},
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
	if !s.opts.Mesh.NoIPv4 && !s.opts.Raft.PreferIPv6 {
		raftAddr = net.JoinHostPort(privatev4.Addr().String(), strconv.Itoa(int(s.raft.ListenPort())))
	} else {
		raftAddr = net.JoinHostPort(self.PrivateIPv6.Addr().String(), strconv.Itoa(int(s.raft.ListenPort())))
	}
	// Start network resources
	s.log.Info("Starting network manager")
	opts := &meshnet.StartOptions{
		Key:       wireguardKey,
		AddressV4: privatev4,
		AddressV6: self.PrivateIPv6,
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
	// We need to readd ourselves server to the cluster as a voter with the acquired raft address.
	s.log.Info("re-adding ourselves to the cluster with the acquired wireguard address")
	err = s.raft.AddVoter(ctx, s.ID(), raftAddr)
	if err != nil {
		return fmt.Errorf("add voter: %w", err)
	}
	s.log.Info("initial bootstrap complete")
	return nil
}
