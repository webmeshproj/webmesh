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

	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshnet"
	"github.com/webmeshproj/webmesh/pkg/meshnet/netutil"
	"github.com/webmeshproj/webmesh/pkg/services/leaderproxy"
	"github.com/webmeshproj/webmesh/pkg/services/rbac"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
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
	if !s.storage.Consensus().IsLeader() {
		return nil, status.Errorf(codes.FailedPrecondition, "not leader")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	log := s.log.With("op", "join", "id", req.GetId())
	ctx = context.WithLogger(ctx, log)

	log.Info("Join request received", slog.Any("request", req))
	// Check if we haven't loaded the mesh domain and prefixes into memory yet
	err := s.loadMeshState(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load mesh state: %v", err)
	}

	// Validate inputs
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "node id required")
	} else if !types.IsValidNodeID(req.GetId()) {
		return nil, status.Error(codes.InvalidArgument, "node id is invalid")
	}

	if s.plugins.HasAuth() {
		if !nodeIDMatchesContext(ctx, req.GetId()) {
			return nil, status.Errorf(codes.PermissionDenied, "node id %s does not match authenticated caller", req.GetId())
		}
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
	publicKey, err := crypto.DecodePublicKey(req.GetPublicKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid public key: %v", err)
	}
	var storagePort int32
	if req.GetAsVoter() || req.GetAsObserver() {
		for _, feat := range req.GetFeatures() {
			if feat.Feature == v1.Feature_STORAGE_PROVIDER {
				storagePort = feat.Port
				break
			}
		}
		if storagePort <= 0 {
			return nil, status.Error(codes.InvalidArgument, "storage provider port required")
		}
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
		for peer := range req.GetDirectPeers() {
			actions = append(actions, canPutEdgeAction.For(peer))
		}
	}
	if len(actions) > 0 {
		allowed, err := s.rbac.Evaluate(ctx, actions)
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
		created, err := s.ensurePeerRoutes(ctx, types.NodeID(req.GetId()), req.GetRoutes())
		if err != nil {
			return nil, handleErr(status.Errorf(codes.Internal, "failed to ensure peer routes: %v", err))
		} else if created {
			cleanFuncs = append(cleanFuncs, func() {
				err := s.storage.MeshDB().Networking().DeleteRoute(ctx, nodeAutoRoute(types.NodeID(req.GetId())))
				if err != nil {
					log.Warn("Failed to delete route", slog.String("error", err.Error()))
				}
			})
		}
	}

	var leasev4, leasev6 netip.Prefix
	// We always generate an IPv6 address for the peer from their public key
	leasev6 = netutil.AssignToPrefix(s.ipv6Prefix, publicKey)
	log.Debug("Assigned IPv6 address to peer", slog.String("ipv6", leasev6.String()))
	// Acquire an IPv4 address for the peer only if requested
	if req.GetAssignIPv4() {
		log.Debug("Assigning IPv4 address to peer")
		leasev4, err = s.plugins.AllocateIP(ctx, &v1.AllocateIPRequest{
			NodeID: req.GetId(),
			Subnet: s.ipv4Prefix.String(),
		})
		if err != nil {
			return nil, handleErr(status.Errorf(codes.Internal, "failed to allocate IPv4 address: %v", err))
		}
		log.Debug("Assigned IPv4 address to peer", slog.String("ipv4", leasev4.String()))
	}
	// Write the peer to the database
	p := s.storage.MeshDB().Peers()
	err = p.Put(ctx, types.MeshNode{MeshNode: &v1.MeshNode{
		Id:                 req.GetId(),
		PrimaryEndpoint:    req.GetPrimaryEndpoint(),
		WireguardEndpoints: req.GetWireguardEndpoints(),
		ZoneAwarenessID:    req.GetZoneAwarenessID(),
		PublicKey:          req.GetPublicKey(),
		PrivateIPv4:        leasev4.String(),
		PrivateIPv6:        leasev6.String(),
		Features:           req.GetFeatures(),
		Multiaddrs:         req.GetMultiaddrs(),
		JoinedAt:           timestamppb.New(time.Now().UTC()),
	}})
	if err != nil {
		return nil, handleErr(status.Errorf(codes.Internal, "failed to persist peer details to storage: %v", err))
	}
	cleanFuncs = append(cleanFuncs, func() {
		err := p.Delete(ctx, types.NodeID(req.GetId()))
		if err != nil {
			log.Warn("failed to delete peer", slog.String("error", err.Error()))
		}
	})
	// At this point we want to
	// Add an edge from the joining server to the caller
	joiningServer := s.nodeID
	if proxiedFrom, ok := leaderproxy.ProxiedFrom(ctx); ok {
		joiningServer = types.NodeID(proxiedFrom)
	}
	log.Debug("Adding edge between caller and joining server", slog.String("join-edge", joiningServer.String()))
	err = p.PutEdge(ctx, types.MeshEdge{MeshEdge: &v1.MeshEdge{
		Source: joiningServer.String(),
		Target: req.GetId(),
		Weight: 1,
	}})
	if err != nil {
		return nil, handleErr(status.Errorf(codes.Internal, "failed to add edge: %v", err))
	}
	if req.GetPrimaryEndpoint() != "" {
		// Add an edge between the caller and all other nodes with public endpoints
		// TODO: This should be done according to network policy and batched
		allPeers, err := p.List(ctx, storage.FilterByIsPublic())
		if err != nil {
			return nil, handleErr(status.Errorf(codes.Internal, "failed to list peers: %v", err))
		}
		for _, peer := range allPeers {
			if peer.GetId() != req.GetId() && peer.PrimaryEndpoint != "" {
				log.Debug("adding edge from public peer to public caller", slog.String("peer", peer.GetId()))
				err = p.PutEdge(ctx, types.MeshEdge{MeshEdge: &v1.MeshEdge{
					Source: peer.GetId(),
					Target: req.GetId(),
					Weight: 99,
				}})
				if err != nil {
					return nil, handleErr(status.Errorf(codes.Internal, "failed to add edge: %v", err))
				}
			}
		}
	}
	if req.GetZoneAwarenessID() != "" {
		// Add an edge between the caller and all other nodes in the same zone
		// with public endpoints.
		// TODO: Same as above - this should be done according to network policy and batched
		zonePeers, err := p.List(ctx, storage.FilterByZoneID(req.GetZoneAwarenessID()))
		if err != nil {
			return nil, handleErr(status.Errorf(codes.Internal, "failed to list peers: %v", err))
		}
		for _, peer := range zonePeers {
			if peer.GetId() == req.GetId() || peer.PrimaryEndpoint == "" {
				continue
			}
			log.Debug("Adding edges to peer in the same zone", slog.String("peer", peer.GetId()))
			if peer.GetId() != req.GetId() {
				err = p.PutEdge(ctx, types.MeshEdge{MeshEdge: &v1.MeshEdge{
					Source: peer.GetId(),
					Target: req.GetId(),
					Weight: 1,
				}})
				if err != nil {
					return nil, handleErr(status.Errorf(codes.Internal, "failed to add edge: %v", err))
				}
			}
		}
	}

	if len(req.GetDirectPeers()) > 0 {
		// Put an edge between the caller and all direct peers
		for peer, proto := range req.GetDirectPeers() {
			// Check if the peer exists
			if !types.IsValidNodeID(peer) {
				return nil, handleErr(status.Errorf(codes.InvalidArgument, "invalid peer id %q", peer))
			}
			_, err := p.Get(ctx, types.NodeID(peer))
			if err != nil {
				if !errors.IsNodeNotFound(err) {
					return nil, handleErr(status.Errorf(codes.Internal, "failed to get peer: %v", err))
				}
				// The peer doesn't exist, so create a placeholder for it
				log.Debug("Registering empty peer", slog.String("peer", peer))
				err = p.Put(ctx, types.MeshNode{MeshNode: &v1.MeshNode{Id: peer}})
				if err != nil {
					return nil, handleErr(status.Errorf(codes.Internal, "failed to register peer: %v", err))
				}
			}
			log.Debug("Adding ICE edge to peer", slog.String("peer", peer))
			err = p.PutEdge(ctx, types.MeshEdge{MeshEdge: &v1.MeshEdge{
				Source:     peer,
				Target:     req.GetId(),
				Weight:     1,
				Attributes: types.EdgeAttrsForConnectProto(proto),
			}})
			if err != nil {
				return nil, handleErr(status.Errorf(codes.Internal, "failed to add edge: %v", err))
			}
		}
	}

	// Collect the list of peers we will send to the new node
	peers, err := meshnet.WireGuardPeersFor(ctx, s.storage.MeshDB(), types.NodeID(req.GetId()))
	if err != nil {
		return nil, handleErr(status.Errorf(codes.Internal, "failed to get wireguard peers: %v", err))
	}

	// Start building the response
	resp := &v1.JoinResponse{
		MeshDomain:  s.meshDomain,
		NetworkIPv4: s.ipv4Prefix.String(),
		NetworkIPv6: s.ipv6Prefix.String(),
		AddressIPv6: leasev6.String(),
		AddressIPv4: func() string {
			if leasev4.IsValid() {
				return leasev4.String()
			}
			return ""
		}(),
		Peers: peers,
	}

	// Add the node to Raft if requested
	// The node will otherwise need to subscribe to cluster events manually with
	// the Subscribe RPC.
	if req.GetAsVoter() || req.GetAsObserver() {
		// Add peer to the raft cluster
		addStorageMember := func() {
			// Wait for the call to be complete before adding the storage member
			// To give the caller a better chance at being ready before the
			// first heartbeat.
			<-ctx.Done()
			var storageAddress string
			if req.GetAssignIPv4() && !req.GetPreferStorageIPv6() {
				// Prefer IPv4 for raft
				storageAddress = net.JoinHostPort(leasev4.Addr().String(), strconv.Itoa(int(storagePort)))
			} else {
				// Use IPv6 for raft
				storageAddress = net.JoinHostPort(leasev6.Addr().String(), strconv.Itoa(int(storagePort)))
			}
			if req.GetAsVoter() {
				log.Info("Adding voter to cluster", slog.String("raft_address", storageAddress))
				if err := s.storage.Consensus().AddVoter(ctx, types.StoragePeer{StoragePeer: &v1.StoragePeer{
					Id:        req.GetId(),
					PublicKey: req.GetPublicKey(),
					Address:   storageAddress,
				}}); err != nil {
					log.Error("Failed to add voter", slog.String("error", err.Error()))
					return
				}
			} else if req.GetAsObserver() {
				log.Info("Adding observer to cluster", slog.String("raft_address", storageAddress))
				if err := s.storage.Consensus().AddObserver(ctx, types.StoragePeer{StoragePeer: &v1.StoragePeer{
					Id:        req.GetId(),
					PublicKey: req.GetPublicKey(),
					Address:   storageAddress,
				}}); err != nil {
					log.Error("Failed to add observer", slog.String("error", err.Error()))
					return
				}
			}
		}
		go addStorageMember()
	}

	dnsServers, err := p.List(ctx, storage.FilterByFeature(v1.Feature_MESH_DNS))
	if err != nil {
		log.Warn("Could not lookup DNS servers for peer", slog.String("error", err.Error()))
	} else {
		for _, peer := range dnsServers {
			if peer.GetId() == req.GetId() {
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

	var requiresICE bool
	for _, peer := range peers {
		if peer.GetNode().GetPrimaryEndpoint() == "" || peer.Proto == v1.ConnectProtocol_CONNECT_ICE {
			requiresICE = true
			break
		}
	}

	// If the caller needs ICE servers, find all the eligible peers and return them
	if requiresICE {
		peers, err := p.List(ctx, storage.FilterByFeature(v1.Feature_ICE_NEGOTIATION))
		if err != nil {
			return nil, handleErr(status.Errorf(codes.Internal, "failed to list peers by ICE feature: %v", err))
		}
		for _, peer := range peers {
			if peer.GetId() == req.GetId() {
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
			log.Warn("No peers with ICE negotiation feature found, node is on its own")
		}
	}

	go func() {
		// Notify any watching plugins
		if s.plugins != nil && s.plugins.HasWatchers() {
			err := s.plugins.Emit(context.Background(), &v1.Event{
				Type: v1.Event_NODE_JOIN,
				Event: &v1.Event_Node{
					Node: &v1.MeshNode{
						Id:                 req.GetId(),
						PrimaryEndpoint:    req.GetPrimaryEndpoint(),
						WireguardEndpoints: req.GetWireguardEndpoints(),
						ZoneAwarenessID:    req.GetZoneAwarenessID(),
						PublicKey:          req.GetPublicKey(),
						PrivateIPv4:        leasev4.String(),
						PrivateIPv6:        leasev6.String(),
						Features:           req.GetFeatures(),
						JoinedAt:           timestamppb.New(time.Now().UTC()),
					},
				},
			})
			if err != nil {
				log.Warn("Failed to emit event", slog.String("error", err.Error()))
			}
		}
	}()

	log.Debug("Sending join response", slog.Any("response", resp))
	return resp, nil
}
