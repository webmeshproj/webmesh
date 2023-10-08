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

package meshnode

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/webmeshproj/webmesh/pkg/meshnet"
	netutil "github.com/webmeshproj/webmesh/pkg/meshnet/util"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

func (s *meshStore) bootstrap(ctx context.Context, opts ConnectOptions) error {
	// Check if the mesh network is defined
	s.log.Debug("Checking if cluster is already bootstrapped")
	var bootstrapped bool = true
	_, err := s.Storage().MeshDB().MeshState().GetIPv6Prefix(ctx)
	if err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("get mesh network: %w", err)
		}
		bootstrapped = false
	}
	// We will always attempt to rejoin as a voter
	opts.RequestVote = true
	if bootstrapped {
		// We have data, so the cluster is already bootstrapped.
		s.log.Info("Cluster already bootstrapped, attempting to rejoin as voter")
		return s.join(ctx, opts)
	}
	s.log.Debug("Cluster not yet bootstrapped, attempting to bootstrap")
	isLeader, joinRT, err := opts.Bootstrap.Transport.LeaderElect(ctx)
	if err != nil {
		if errors.IsAlreadyBootstrapped(err) && joinRT != nil {
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
	// We'll bootstrap the cluster as just ourselves.
	s.log.Info("Bootstrapping mesh storage")
	err := s.storage.Bootstrap(ctx)
	if err != nil {
		return fmt.Errorf("bootstrap raft: %w", err)
	}
	bootstrapOpts := storage.BootstrapOptions{
		MeshDomain:           opts.Bootstrap.MeshDomain,
		IPv4Network:          opts.Bootstrap.IPv4Network,
		Admin:                opts.Bootstrap.Admin,
		DefaultNetworkPolicy: opts.Bootstrap.DefaultNetworkPolicy,
		BootstrapNodes:       append(opts.Bootstrap.Servers, s.ID().String()),
		Voters:               opts.Bootstrap.Voters,
		DisableRBAC:          opts.Bootstrap.DisableRBAC,
	}
	results, err := storage.Bootstrap(ctx, s.Storage().MeshDB(), bootstrapOpts)
	if err != nil {
		return fmt.Errorf("bootstrap database: %w", err)
	}
	s.meshDomain = results.MeshDomain
	s.log.Info("Bootstrapped webmesh cluster database",
		slog.String("ipv4-network", opts.Bootstrap.IPv4Network),
		slog.String("ipv6-network", results.NetworkV6.String()),
		slog.String("mesh-domain", s.meshDomain),
	)

	// If we have routes configured, add them to the db
	meshDB := s.Storage().MeshDB()
	if len(opts.Routes) > 0 {
		err = meshDB.Networking().PutRoute(ctx, types.Route{Route: &v1.Route{
			Name: fmt.Sprintf("%s-auto", s.nodeID),
			Node: s.ID().String(),
			DestinationCIDRs: func() []string {
				out := make([]string, 0)
				for _, r := range opts.Routes {
					out = append(out, r.String())
				}
				return out
			}(),
		}})
		if err != nil {
			return fmt.Errorf("create routes: %w", err)
		}
	}

	// We need to officially "join" ourselves to the cluster with a wireguard
	// address. This is done by creating a new node in the database and then
	// readding it to the cluster as a voter with the acquired address.
	s.log.Info("Registering ourselves as a node in the cluster", slog.String("server-id", s.ID().String()))
	p := meshDB.Peers()
	encodedPubKey, err := s.key.PublicKey().Encode()
	if err != nil {
		return fmt.Errorf("encode public key: %w", err)
	}
	privatev6 := netutil.AssignToPrefix(results.NetworkV6, s.key.PublicKey())
	self := types.MeshNode{MeshNode: &v1.MeshNode{
		Id:              s.ID().String(),
		PrimaryEndpoint: opts.PrimaryEndpoint.String(),
		WireguardEndpoints: func() []string {
			out := make([]string, 0)
			for _, ep := range opts.WireGuardEndpoints {
				out = append(out, ep.String())
			}
			return out
		}(),
		ZoneAwarenessID: s.opts.ZoneAwarenessID,
		PublicKey:       encodedPubKey,
		PrivateIPv6:     privatev6.String(),
		Features:        opts.Features,
		JoinedAt:        timestamppb.New(time.Now().UTC()),
	}}
	// Allocate addresses
	var privatev4 netip.Prefix
	if !s.opts.DisableIPv4 {
		privatev4, err = s.plugins.AllocateIP(ctx, &v1.AllocateIPRequest{
			NodeID: s.ID().String(),
			Subnet: opts.Bootstrap.IPv4Network,
		})
		if err != nil {
			return fmt.Errorf("allocate IPv4 address: %w", err)
		}
		self.PrivateIPv4 = privatev4.String()
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
		err = p.Put(ctx, types.MeshNode{MeshNode: &v1.MeshNode{Id: id}})
		if err != nil {
			return fmt.Errorf("create node: %w", err)
		}
	}
	// Do the loop again for edges
	for _, id := range append(opts.Bootstrap.Servers, s.ID().String()) {
		for _, peer := range opts.Bootstrap.Servers {
			if id == peer {
				continue
			}
			s.log.Info("Creating edges in database for bootstrap server",
				slog.String("server-id", id),
				slog.String("peer-id", peer),
			)
			err = p.PutEdge(ctx, types.MeshEdge{MeshEdge: &v1.MeshEdge{
				Source: id,
				Target: peer,
				Weight: 99,
			}})
			if err != nil {
				return fmt.Errorf("create edge: %w", err)
			}
			err = p.PutEdge(ctx, types.MeshEdge{MeshEdge: &v1.MeshEdge{
				Source: id,
				Target: peer,
				Weight: 99,
			}})
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
			err = p.Put(ctx, types.MeshNode{MeshNode: &v1.MeshNode{Id: peer.String()}})
			if err != nil {
				return fmt.Errorf("create direct peerings: %w", err)
			}
			err = p.PutEdge(ctx, types.MeshEdge{MeshEdge: &v1.MeshEdge{
				Source:     s.ID().String(),
				Target:     peer.String(),
				Weight:     0,
				Attributes: types.EdgeAttrsForConnectProto(proto),
			}})
			if err != nil {
				return fmt.Errorf("create direct peerings: %w", err)
			}
		}
	}
	if s.testStore {
		// We dont manage network connections on test stores
		return nil
	}
	// Determine what our storage address will be
	var storageAddr string
	lport := s.storage.ListenPort()
	if !s.opts.DisableIPv4 && !opts.PreferIPv6 {
		storageAddr = net.JoinHostPort(privatev4.Addr().String(), strconv.Itoa(int(lport)))
	} else {
		storageAddr = net.JoinHostPort(privatev6.Addr().String(), strconv.Itoa(int(lport)))
	}
	// Start network resources
	s.log.Info("Starting network manager")
	startopts := meshnet.StartOptions{
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
		NetworkV4: results.NetworkV4,
		NetworkV6: results.NetworkV6,
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
	err = s.storage.Consensus().AddVoter(ctx, &v1.StoragePeer{
		Id:        s.nodeID,
		PublicKey: encodedPubKey,
		Address:   storageAddr,
	})
	if err != nil {
		return fmt.Errorf("add voter: %w", err)
	}
	s.log.Info("Initial network bootstrap complete")
	return nil
}
