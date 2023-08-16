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

package membership

import (
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb/networking"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	"github.com/webmeshproj/webmesh/pkg/net/mesh"
	"github.com/webmeshproj/webmesh/pkg/services/leaderproxy"
	"github.com/webmeshproj/webmesh/pkg/services/rbac"
)

var canVoteAction = &rbac.Action{
	Verb:     v1.RuleVerb_VERB_PUT,
	Resource: v1.RuleResource_RESOURCE_VOTES,
}

var canObserveAction = &rbac.Action{
	Verb:     v1.RuleVerb_VERB_PUT,
	Resource: v1.RuleResource_RESOURCE_OBSERVERS,
}

var canPutRouteAction = &rbac.Action{
	Verb:     v1.RuleVerb_VERB_PUT,
	Resource: v1.RuleResource_RESOURCE_ROUTES,
}

var canPutEdgeAction = &rbac.Action{
	Verb:     v1.RuleVerb_VERB_PUT,
	Resource: v1.RuleResource_RESOURCE_EDGES,
}

func (s *Server) Join(ctx context.Context, req *v1.JoinRequest) (*v1.JoinResponse, error) {
	if !s.store.Raft().IsLeader() {
		return nil, status.Errorf(codes.FailedPrecondition, "not leader")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	log := s.log.With("op", "join", "id", req.GetId())
	ctx = context.WithLogger(ctx, log)

	log.Debug("Join request received", slog.Any("request", req))
	// Check if we haven't loaded the mesh domain and prefixes into memory yet
	err := s.loadMeshState(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load mesh state: %v", err)
	}

	// Validate inputs
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "node id required")
	} else if !peers.IsValidID(req.GetId()) {
		return nil, status.Error(codes.InvalidArgument, "node id is invalid")
	}
	if len(req.GetRoutes()) > 0 {
		for _, route := range req.GetRoutes() {
			route, err := netip.ParsePrefix(route)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid route %q: %v", route, err)
			}
			// Make sure the route does not overlap with a mesh reserved prefix
			if route.Contains(s.ipv4Prefix.Addr()) || route.Contains(s.ipv6Prefix.Addr()) {
				return nil, status.Errorf(codes.InvalidArgument, "route %q overlaps with mesh prefix", route)
			}
		}
	}
	publicKey, err := wgtypes.ParseKey(req.GetPublicKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid public key: %v", err)
	}

	// Check that the node is indeed who they say they are
	if !s.insecure {
		if !nodeIDMatchesContext(ctx, req.GetId()) {
			return nil, status.Errorf(codes.PermissionDenied, "node id %s does not match authenticated caller", req.GetId())
		}
		// We can go ahead and check here if the node is allowed to do what
		// they want.
		var actions rbac.Actions
		if req.GetAsVoter() {
			actions = append(actions, canVoteAction)
		}
		if req.GetAsObserver() {
			// Technically, voters are also observers, but we check it for now
			// for consistency.
			actions = append(actions, canObserveAction)
		}
		if len(req.GetRoutes()) > 0 {
			actions = append(actions, canPutRouteAction)
		}
		if len(req.GetDirectPeers()) > 0 {
			for _, peer := range req.GetDirectPeers() {
				actions = append(actions, canPutEdgeAction.For(peer))
			}
		}
		if len(actions) > 0 {
			allowed, err := s.rbacEval.Evaluate(ctx, actions)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to evaluate permissions: %v", err)
			}
			if !allowed {
				s.log.Warn("Node not allowed to perform requested actions",
					slog.String("id", req.GetId()),
					slog.Any("actions", actions))
				return nil, status.Error(codes.PermissionDenied, "not allowed")
			}
		}
	}

	// Issue a barrier to the raft cluster to ensure all nodes are
	// fully caught up before we make changes
	// TODO: Make timeout configurable
	_, err = s.store.Raft().Barrier(ctx, time.Second*15)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to send barrier: %v", err)
	}

	// Send another barrier after we're done to ensure all nodes are
	// fully caught up before we return
	defer func() {
		_, _ = s.store.Raft().Barrier(ctx, time.Second*15)
	}()

	// Start building a list of clean up functions to run if we fail
	cleanFuncs := make([]func(), 0)
	handleErr := func(cause error) error {
		for _, f := range cleanFuncs {
			f()
		}
		return cause
	}

	// Handle any new routes
	if len(req.GetRoutes()) > 0 {
		created, err := s.ensurePeerRoutes(ctx, req.GetId(), req.GetRoutes())
		if err != nil {
			return nil, handleErr(status.Errorf(codes.Internal, "failed to ensure peer routes: %v", err))
		} else if created {
			cleanFuncs = append(cleanFuncs, func() {
				err := networking.New(s.store.Storage()).DeleteRoute(ctx, nodeAutoRoute(req.GetId()))
				if err != nil {
					log.Warn("Failed to delete route", slog.String("error", err.Error()))
				}
			})
		}
	}

	var leasev4, leasev6 netip.Prefix
	// We always try to generate an IPv6 address for the peer, even if they choose not to
	// use it. This helps enforce an upper bound on the umber of peers we can have in the network
	// (ULA/48 with /64 prefixes == 65536 peers same as a /16 class B and the limit for direct WireGuard
	// peers an interface can hold).
	log.Debug("Assigning IPv6 address to peer")
	leasev6, err = s.store.Plugins().AllocateIP(ctx, &v1.AllocateIPRequest{
		NodeId:  req.GetId(),
		Subnet:  s.ipv6Prefix.String(),
		Version: v1.AllocateIPRequest_IP_VERSION_6,
	})
	if err != nil {
		return nil, handleErr(status.Errorf(codes.Internal, "failed to allocate IPv6 address: %v", err))
	}
	log.Debug("Assigned IPv6 address to peer", slog.String("ipv6", leasev6.String()))
	// Acquire an IPv4 address for the peer only if requested
	if req.GetAssignIpv4() {
		log.Debug("Assigning IPv4 address to peer")
		leasev4, err = s.store.Plugins().AllocateIP(ctx, &v1.AllocateIPRequest{
			NodeId:  req.GetId(),
			Subnet:  s.ipv4Prefix.String(),
			Version: v1.AllocateIPRequest_IP_VERSION_4,
		})
		if err != nil {
			return nil, handleErr(status.Errorf(codes.Internal, "failed to allocate IPv4 address: %v", err))
		}
		log.Debug("Assigned IPv4 address to peer", slog.String("ipv4", leasev4.String()))
	}
	// Write the peer to the database
	p := peers.New(s.store.Storage())
	err = p.Put(ctx, peers.Node{
		ID:                 req.GetId(),
		PublicKey:          publicKey,
		PrimaryEndpoint:    req.GetPrimaryEndpoint(),
		WireGuardEndpoints: req.GetWireguardEndpoints(),
		ZoneAwarenessID:    req.GetZoneAwarenessId(),
		GRPCPort:           int(req.GetGrpcPort()),
		RaftPort:           int(req.GetRaftPort()),
		DNSPort:            int(req.GetMeshdnsPort()),
		Features:           req.GetFeatures(),
		PrivateIPv4:        leasev4,
		PrivateIPv6:        leasev6,
	})
	if err != nil {
		return nil, handleErr(status.Errorf(codes.Internal, "failed to persist peer details to raft log: %v", err))
	}
	cleanFuncs = append(cleanFuncs, func() {
		err := p.Delete(ctx, req.GetId())
		if err != nil {
			log.Warn("failed to delete peer", slog.String("error", err.Error()))
		}
	})
	// At this point we want to
	// Add an edge from the joining server to the caller
	joiningServer := string(s.store.ID())
	if proxiedFrom, ok := leaderproxy.ProxiedFrom(ctx); ok {
		joiningServer = proxiedFrom
	}
	log.Debug("adding edge between caller and joining server", slog.String("joining_server", joiningServer))
	err = p.PutEdge(ctx, peers.Edge{
		From:   joiningServer,
		To:     req.GetId(),
		Weight: 1,
	})
	if err != nil {
		return nil, handleErr(status.Errorf(codes.Internal, "failed to add edge: %v", err))
	}
	if req.GetPrimaryEndpoint() != "" {
		// Add an edge between the caller and all other nodes with public endpoints
		// TODO: This should be done according to network policy and batched
		allPeers, err := p.ListPublicNodes(ctx)
		if err != nil {
			return nil, handleErr(status.Errorf(codes.Internal, "failed to list peers: %v", err))
		}
		for _, peer := range allPeers {
			if peer.ID != req.GetId() && peer.PrimaryEndpoint != "" {
				log.Debug("adding edge from public peer to public caller", slog.String("peer", peer.ID))
				err = p.PutEdge(ctx, peers.Edge{
					From:   peer.ID,
					To:     req.GetId(),
					Weight: 99,
				})
				if err != nil {
					return nil, handleErr(status.Errorf(codes.Internal, "failed to add edge: %v", err))
				}
			}
		}
	}
	if req.GetZoneAwarenessId() != "" {
		// Add an edge between the caller and all other nodes in the same zone
		// with public endpoints.
		// TODO: Same as above - this should be done according to network policy and batched
		zonePeers, err := p.ListByZoneID(ctx, req.GetZoneAwarenessId())
		if err != nil {
			return nil, handleErr(status.Errorf(codes.Internal, "failed to list peers: %v", err))
		}
		for _, peer := range zonePeers {
			if peer.ID == req.GetId() || peer.PrimaryEndpoint == "" {
				continue
			}
			log.Debug("Adding edges to peer in the same zone", slog.String("peer", peer.ID))
			if peer.ID != req.GetId() {
				err = p.PutEdge(ctx, peers.Edge{
					From:   peer.ID,
					To:     req.GetId(),
					Weight: 1,
				})
				if err != nil {
					return nil, handleErr(status.Errorf(codes.Internal, "failed to add edge: %v", err))
				}
			}
		}
	}

	if len(req.GetDirectPeers()) > 0 {
		// Put an ICE edge between the caller and all direct peers
		for _, peer := range req.GetDirectPeers() {
			// Check if the peer exists
			_, err := p.Get(ctx, peer)
			if err != nil {
				if err != peers.ErrNodeNotFound {
					return nil, handleErr(status.Errorf(codes.Internal, "failed to get peer: %v", err))
				}
				// The peer doesn't exist, so create a placeholder for it
				log.Debug("Registering empty peer", slog.String("peer", peer))
				err = p.Put(ctx, peers.Node{
					ID: peer,
				})
				if err != nil {
					return nil, handleErr(status.Errorf(codes.Internal, "failed to register peer: %v", err))
				}
			}
			log.Debug("Adding ICE edge to peer", slog.String("peer", peer))
			err = p.PutEdge(ctx, peers.Edge{
				From:   peer,
				To:     req.GetId(),
				Weight: 1,
				Attrs: map[string]string{
					v1.EdgeAttributes_EDGE_ATTRIBUTE_ICE.String(): "true",
				},
			})
			if err != nil {
				return nil, handleErr(status.Errorf(codes.Internal, "failed to add edge: %v", err))
			}
		}
	}

	// Add the node to Raft if requested
	// The node will otherwise need to subscribe to cluster events manually with
	// the Subscribe RPC.
	if req.GetAsVoter() || req.GetAsObserver() {
		// Add peer to the raft cluster
		var raftAddress string
		if req.GetAssignIpv4() && !req.GetPreferRaftIpv6() {
			// Prefer IPv4 for raft
			raftAddress = net.JoinHostPort(leasev4.Addr().String(), strconv.Itoa(int(req.GetRaftPort())))
		} else {
			// Use IPv6 for raft
			raftAddress = net.JoinHostPort(leasev6.Addr().String(), strconv.Itoa(int(req.GetRaftPort())))
		}
		if req.GetAsVoter() {
			log.Info("Adding voter to cluster", slog.String("raft_address", raftAddress))
			if err := s.store.Raft().AddVoter(ctx, req.GetId(), raftAddress); err != nil {
				return nil, handleErr(status.Errorf(codes.Internal, "failed to add voter: %v", err))
			}
		} else if req.GetAsObserver() {
			log.Info("Adding observer to cluster", slog.String("raft_address", raftAddress))
			if err := s.store.Raft().AddNonVoter(ctx, req.GetId(), raftAddress); err != nil {
				return nil, handleErr(status.Errorf(codes.Internal, "failed to add non-voter: %v", err))
			}
		}
		cleanFuncs = append(cleanFuncs, func() {
			err := s.store.Raft().RemoveServer(ctx, req.GetId(), false)
			if err != nil {
				log.Warn("Failed to remove voter", slog.String("error", err.Error()))
			}
		})
	}

	// Start building the response
	resp := &v1.JoinResponse{
		MeshDomain:  s.meshDomain,
		NetworkIpv4: s.ipv4Prefix.String(),
		NetworkIpv6: s.ipv6Prefix.String(),
		AddressIpv6: leasev6.String(),
		AddressIpv4: func() string {
			if leasev4.IsValid() {
				return leasev4.String()
			}
			return ""
		}(),
	}
	dnsServers, err := p.ListByFeature(ctx, v1.Feature_MESH_DNS)
	if err != nil {
		log.Warn("could not lookup DNS servers", slog.String("error", err.Error()))
	} else {
		for _, peer := range dnsServers {
			if peer.ID == req.GetId() {
				continue
			}
			switch {
			// Prefer the IPv4 address
			case peer.PrivateDNSAddrV4().IsValid():
				resp.DnsServers = append(resp.DnsServers, peer.PrivateDNSAddrV4().String())
			case peer.PrivateDNSAddrV6().IsValid():
				resp.DnsServers = append(resp.DnsServers, peer.PrivateDNSAddrV6().String())
			}
		}
	}
	peers, err := mesh.WireGuardPeersFor(ctx, s.store.Storage(), req.GetId())
	if err != nil {
		return nil, handleErr(status.Errorf(codes.Internal, "failed to get wireguard peers: %v", err))
	}
	var requiresICE bool
	for _, peer := range peers {
		if peer.PrimaryEndpoint == "" || peer.Ice {
			requiresICE = true
			break
		}
	}
	resp.Peers = peers

	// If the caller needs ICE servers, find all the eligible peers and return them
	if requiresICE {
		peers, err := p.ListByFeature(ctx, v1.Feature_ICE_NEGOTIATION)
		if err != nil {
			return nil, handleErr(status.Errorf(codes.Internal, "failed to list peers by ICE feature: %v", err))
		}
		for _, peer := range peers {
			if peer.ID == req.GetId() {
				continue
			}
			// We only return peers that are publicly accessible for now.
			// This should be configurable in the future.
			publicAddr := peer.PublicRPCAddr()
			if publicAddr.IsValid() {
				resp.IceServers = append(resp.IceServers, publicAddr.String())
			}
		}
		if len(resp.IceServers) == 0 {
			log.Warn("no peers with ICE negotiation feature found, node is on its own")
		}
	}

	log.Debug("Sending join response", slog.Any("response", resp))
	return resp, nil
}
