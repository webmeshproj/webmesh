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

package node

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/meshdb/peers"
	"github.com/webmeshproj/node/pkg/net/mesh"
	"github.com/webmeshproj/node/pkg/services/leaderproxy"
	"github.com/webmeshproj/node/pkg/services/rbac"
)

var canVoteAction = &rbac.Action{
	Verb:     v1.RuleVerb_VERB_PUT,
	Resource: v1.RuleResource_RESOURCE_VOTES,
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
	if !s.store.IsLeader() {
		return nil, status.Errorf(codes.FailedPrecondition, "not leader")
	}
	// Check if we haven't loaded out prefixes into memory yet
	var err error
	if !s.ipv6Prefix.IsValid() {
		s.ipv6Prefix, err = s.meshstate.GetIPv6Prefix(ctx)
		if err != nil {
			// DB error, bail
			return nil, status.Errorf(codes.Internal, "failed to get IPv6 prefix: %v", err)
		}
	}
	if !s.ipv4Prefix.IsValid() {
		s.ipv4Prefix, err = s.meshstate.GetIPv4Prefix(ctx)
		if err != nil {
			// DB error, bail
			return nil, status.Errorf(codes.Internal, "failed to get IPv4 prefix: %v", err)
		}
	}

	// Validate inputs
	if req.GetId() == "" {
		// TODO: This is technically not required if we are using authenticated gRPC
		return nil, status.Error(codes.InvalidArgument, "node id required")
	} else if !peers.IsValidID(req.GetId()) {
		// TODO: Have a list of invalid characters
		return nil, status.Error(codes.InvalidArgument, "node id is invalid")
	}
	if len(req.GetRoutes()) > 0 {
		for _, route := range req.GetRoutes() {
			_, err := netip.ParsePrefix(route)
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "invalid route %q: %v", route, err)
			}
		}
	}

	// Check that the node is indeed who they say they are
	if !s.insecure {
		if proxiedFor, ok := leaderproxy.ProxiedFor(ctx); ok {
			if proxiedFor != req.GetId() {
				return nil, status.Errorf(codes.PermissionDenied, "proxied for %s, not %s", proxiedFor, req.GetId())
			}
		} else {
			if peer, ok := context.AuthenticatedCallerFrom(ctx); ok {
				if peer != req.GetId() {
					return nil, status.Errorf(codes.PermissionDenied, "peer id %s, not %s", peer, req.GetId())
				}
			} else {
				return nil, status.Error(codes.PermissionDenied, "no peer authentication info in context")
			}
		}
		// We can go ahead and check here if the node is allowed to do what
		// they want.
		var actions rbac.Actions
		if req.GetAsVoter() {
			actions = append(actions, canVoteAction)
		}
		if len(req.GetRoutes()) > 0 {
			actions = append(actions, canPutRouteAction)
		}
		if len(req.GetDirectPeers()) > 0 {
			for _, peer := range req.GetDirectPeers() {
				actions = append(actions, canPutEdgeAction.For(peer))
				actions = append(actions, canNegDataChannelAction.For(peer)...)
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

	publicKey, err := wgtypes.ParseKey(req.GetPublicKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid public key: %v", err)
	}

	log := s.log.With("id", req.GetId())

	// Issue a barrier to the raft cluster to ensure all nodes are
	// fully caught up before we start assigning it addresses
	log.Info("sending barrier to raft cluster")
	timeout := time.Second * 10 // TODO: Make this configurable
	err = s.store.Raft().Barrier(timeout).Error()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to send barrier: %v", err)
	}
	log.Debug("barrier complete, all nodes caught up")

	// Lookup the peer in the database
	var peer peers.Node
	peer, err = s.peers.Get(ctx, req.GetId())
	if err != nil && err != peers.ErrNodeNotFound {
		// Database error
		return nil, status.Errorf(codes.Internal, "failed to get peer: %v", err)
	} else if err == nil {
		log.Info("peer already exists, updating")
		// Peer already exists, update it
		peer, err = s.peers.Put(ctx, &peers.PutOptions{
			ID:                 req.GetId(),
			PublicKey:          publicKey,
			PrimaryEndpoint:    req.GetPrimaryEndpoint(),
			WireGuardEndpoints: req.GetWireguardEndpoints(),
			ZoneAwarenessID:    req.GetZoneAwarenessId(),
			GRPCPort:           int(req.GetGrpcPort()),
			RaftPort:           int(req.GetRaftPort()),
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to update peer: %v", err)
		}
	} else {
		// New peer, create it
		log.Info("registering new peer")
		peer, err = s.peers.Put(ctx, &peers.PutOptions{
			ID:                 req.GetId(),
			PublicKey:          publicKey,
			PrimaryEndpoint:    req.GetPrimaryEndpoint(),
			WireGuardEndpoints: req.GetWireguardEndpoints(),
			ZoneAwarenessID:    req.GetZoneAwarenessId(),
			GRPCPort:           int(req.GetGrpcPort()),
			RaftPort:           int(req.GetRaftPort()),
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create peer: %v", err)
		}
	}

	// Handle any new routes
	if len(req.GetRoutes()) > 0 {
		current, err := s.networking.GetRoutesByNode(ctx, req.GetId())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to get current routes: %v", err)
		}
		for _, route := range req.GetRoutes() {
			// Check if the node is already assigned this route
			var found bool
			for _, r := range current {
				for _, cidr := range r.DestinationCidrs {
					if cidr == route {
						found = true
						break
					}
				}
			}
			if found {
				continue
			}
			// Add a new route
			err = s.networking.PutRoute(ctx, &v1.Route{
				Name:             fmt.Sprintf("%s-auto", req.GetId()),
				Node:             req.GetId(),
				DestinationCidrs: req.GetRoutes(),
			})
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to add route: %v", err)
			}
			break
		}
	}

	var leasev4, leasev6 netip.Prefix
	// We always try to generate an IPv6 address for the peer, even if they choose not to
	// use it. This helps enforce an upper bound on the umber of peers we can have in the network
	// (ULA/48 with /64 prefixes == 65536 peers same as a /16 class B and the limit for direct WireGuard
	// peers an interface can hold).
	log.Debug("assigning IPv6 address to peer")
	leasev6, err = s.store.Plugins().AllocateIP(ctx, &v1.AllocateIPRequest{
		NodeId:  req.GetId(),
		Subnet:  s.ipv6Prefix.String(),
		Version: v1.AllocateIPRequest_IP_VERSION_6,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to allocate IPv6 address: %v", err)
	}
	log.Debug("assigned IPv6 address to peer", slog.String("ipv6", leasev6.String()))
	// Acquire an IPv4 address for the peer only if requested
	if req.GetAssignIpv4() {
		log.Debug("assigning IPv4 address to peer")
		leasev4, err = s.store.Plugins().AllocateIP(ctx, &v1.AllocateIPRequest{
			NodeId:  req.GetId(),
			Subnet:  s.ipv4Prefix.String(),
			Version: v1.AllocateIPRequest_IP_VERSION_4,
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to allocate IPv4 address: %v", err)
		}
		log.Debug("assigned IPv4 address to peer", slog.String("ipv4", leasev4.String()))
	}
	// Persist the peer's addresses
	err = s.peers.PutLease(ctx, &peers.PutLeaseOptions{
		ID:   req.GetId(),
		IPv4: leasev4,
		IPv6: leasev6,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to persist peer's addresses: %v", err)
	}
	// Add an edge from the joining server to the caller
	joiningServer := string(s.store.ID())
	if proxiedFrom, ok := leaderproxy.ProxiedFrom(ctx); ok {
		joiningServer = proxiedFrom
	}
	log.Debug("adding edge between caller and joining server", slog.String("joining_server", joiningServer))
	err = s.peers.PutEdge(ctx, peers.Edge{
		From:   joiningServer,
		To:     req.GetId(),
		Weight: 1,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to add edge: %v", err)
	}
	if req.GetPrimaryEndpoint() != "" {
		// Add an edge between the caller and all other nodes with public endpoints
		// TODO: This should be done according to network policy and batched
		allPeers, err := s.peers.ListPublicNodes(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to list peers: %v", err)
		}
		for _, peer := range allPeers {
			if peer.ID != req.GetId() && peer.PrimaryEndpoint != "" {
				log.Debug("adding edge from public peer to public caller", slog.String("peer", peer.ID))
				err = s.peers.PutEdge(ctx, peers.Edge{
					From:   peer.ID,
					To:     req.GetId(),
					Weight: 99,
				})
				if err != nil {
					return nil, status.Errorf(codes.Internal, "failed to add edge: %v", err)
				}
			}
		}
	}
	if req.GetZoneAwarenessId() != "" {
		// Add an edge between the caller and all other nodes in the same zone
		// with public endpoints.
		// TODO: Same as above - this should be done according to network policy and batched
		zonePeers, err := s.peers.ListByZoneID(ctx, req.GetZoneAwarenessId())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to list peers: %v", err)
		}
		for _, peer := range zonePeers {
			if peer.ID == req.GetId() || peer.PrimaryEndpoint == "" {
				continue
			}
			log.Debug("adding edges to peer in the same zone", slog.String("peer", peer.ID))
			if peer.ID != req.GetId() {
				err = s.peers.PutEdge(ctx, peers.Edge{
					From:   peer.ID,
					To:     req.GetId(),
					Weight: 1,
				})
				if err != nil {
					return nil, status.Errorf(codes.Internal, "failed to add edge: %v", err)
				}
			}
		}
	}

	if len(req.GetDirectPeers()) > 0 {
		// Put an ICE edge between the caller and all direct peers
		for _, peer := range req.GetDirectPeers() {
			err = s.peers.PutEdge(ctx, peers.Edge{
				From:   peer,
				To:     req.GetId(),
				Weight: 1,
				Attrs: map[string]string{
					v1.EdgeAttributes_EDGE_ATTRIBUTE_ICE.String(): "true",
				},
			})
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to add edge: %v", err)
			}
		}
	}

	// Add peer to the raft cluster
	var raftAddress string
	if req.GetAssignIpv4() && !req.GetPreferRaftIpv6() {
		// Prefer IPv4 for raft
		raftAddress = net.JoinHostPort(leasev4.Addr().String(), strconv.Itoa(peer.RaftPort))
	} else {
		// Use IPv6
		// TODO: doesn't work when we are IPv4 only. Need to fix this.
		// Basically if a single node is IPv4 only, we need to use IPv4 for raft.
		// We may as well use IPv4 for everything in that case. Leave it for now,
		// but need to document these requirements fully for dual-stack setups.
		raftAddress = net.JoinHostPort(leasev6.Addr().String(), strconv.Itoa(peer.RaftPort))
	}
	if req.GetAsVoter() {
		log.Info("adding candidate to cluster", slog.String("raft_address", raftAddress))
		if err := s.store.AddVoter(ctx, req.GetId(), raftAddress); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to add voter: %v", err)
		}
	} else {
		log.Info("adding non-voter to cluster", slog.String("raft_address", raftAddress))
		if err := s.store.AddNonVoter(ctx, req.GetId(), raftAddress); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to add non-voter: %v", err)
		}
	}

	// Start building the response
	resp := &v1.JoinResponse{
		NetworkIpv6: s.ipv6Prefix.String(),
		AddressIpv6: leasev6.String(),
		AddressIpv4: func() string {
			if leasev4.IsValid() {
				return leasev4.String()
			}
			return ""
		}(),
	}
	peers, err := mesh.WireGuardPeersFor(ctx, s.store, req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get wireguard peers: %v", err)
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
		iceAddrs, err := s.meshstate.ListPublicPeersWithFeature(ctx, s.proxyCreds, req.GetId(), v1.Feature_ICE_NEGOTIATION)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to list peers: %v", err)
		}
		for _, addr := range iceAddrs {
			resp.IceServers = append(resp.IceServers, addr.String())
		}
		if len(resp.IceServers) == 0 {
			log.Warn("no peers with ICE negotiation feature found, rejecting join request")
			return nil, status.Errorf(codes.FailedPrecondition, "no peers with ICE negotiation feature found")
		}
	}

	// Notify any watchers that a new peer has joined
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var status v1.ClusterStatus
		if req.GetAsVoter() {
			status = v1.ClusterStatus_CLUSTER_VOTER
		} else {
			status = v1.ClusterStatus_CLUSTER_NON_VOTER
		}
		node := peer.Proto(status)
		err := s.store.Plugins().Emit(ctx, &v1.Event{
			Type:  v1.WatchEvent_WATCH_EVENT_NODE_JOIN,
			Event: &v1.Event_Node{Node: node},
		})
		if err != nil {
			log.Error("failed to emit event", slog.String("error", err.Error()))
		}
	}()

	log.Debug("sending join response", slog.Any("response", resp))
	return resp, nil
}
