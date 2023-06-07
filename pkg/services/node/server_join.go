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

package node

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/node/pkg/meshdb/peers"
	"github.com/webmeshproj/node/pkg/services/leaderproxy"
	"github.com/webmeshproj/node/pkg/util"
)

var canVoteAction = &v1.Action{
	Verb:     v1.RuleVerbs_VERB_PUT,
	Resource: v1.RuleResource_RESOURCE_VOTES,
}

func (s *Server) Join(ctx context.Context, req *v1.JoinRequest) (*v1.JoinResponse, error) {
	if !s.store.IsLeader() {
		return nil, status.Errorf(codes.FailedPrecondition, "not leader")
	}

	// Validate inputs
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "node id required")
	}

	// TODO: When using mTLS, we should verify the peer certificate
	// matches the node ID. A proxy server will need to pass the
	// certificate through to the node server.

	// We can go ahead and check here if the node is allowed to do what
	// they want
	if req.GetAsVoter() {
		roles, err := s.rbac.ListNodeRoles(ctx, req.GetId())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to list node roles: %v", err)
		}
		allowed := roles.EvalAction(canVoteAction)
		if !allowed {
			s.log.Warn("Node not allowed to join as voter", slog.String("id", req.GetId()))
			return nil, status.Error(codes.PermissionDenied, "not allowed")
		}
	}

	if !s.ulaPrefix.IsValid() {
		var err error
		s.ulaPrefix, err = s.meshstate.GetULAPrefix(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to get ULA prefix: %v", err)
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

	// Check if the peer already exists
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
			NetworkIPv6:        peer.NetworkIPv6,
			GRPCPort:           int(req.GetGrpcPort()),
			RaftPort:           int(req.GetRaftPort()),
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to update peer: %v", err)
		}
	} else {
		// New peer, create it
		log.Info("registering new peer")
		networkIPv6, err := util.Random64(s.ulaPrefix)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to generate IPv6 address: %v", err)
		}
		peer, err = s.peers.Put(ctx, &peers.PutOptions{
			ID:                 req.GetId(),
			PublicKey:          publicKey,
			PrimaryEndpoint:    req.GetPrimaryEndpoint(),
			WireGuardEndpoints: req.GetWireguardEndpoints(),
			ZoneAwarenessID:    req.GetZoneAwarenessId(),
			NetworkIPv6:        networkIPv6,
			GRPCPort:           int(req.GetGrpcPort()),
			RaftPort:           int(req.GetRaftPort()),
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to create peer: %v", err)
		}
	}

	// Acquire an IPv4 address for the peer if requested
	var lease netip.Prefix
	if req.GetAssignIpv4() {
		log.Debug("assigning IPv4 address to peer")
		lease, err = s.ipam.Acquire(ctx, req.GetId())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to assign IPv4: %v", err)
		}
		log.Info("assigned IPv4 address to peer", slog.String("ipv4", lease.String()))
	}

	// TODO: Evaluate network policy to determine edges

	// Add an edge from the joining server to the caller
	joiningServer := string(s.store.ID())
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		proxiedFrom := md.Get(leaderproxy.ProxiedFromMeta)
		if len(proxiedFrom) > 0 {
			// The request was proxied, so the joining server is the
			// server that proxied the request
			joiningServer = proxiedFrom[0]
		}
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
		zonePeers, err := s.peers.ListByZoneID(ctx, req.GetZoneAwarenessId())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to list peers: %v", err)
		}
		for _, peer := range zonePeers {
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

	// Add peer to the raft cluster
	var raftAddress string
	if req.GetAssignIpv4() && !req.GetPreferRaftIpv6() {
		// Prefer IPv4 for raft
		raftAddress = net.JoinHostPort(lease.Addr().String(), strconv.Itoa(peer.RaftPort))
	} else {
		// Use IPv6
		// TODO: doesn't work when we are IPv4 only. Need to fix this.
		// Basically if a single node is IPv4 only, we need to use IPv4 for raft.
		// We may as well use IPv4 for everything in that case. Leave it for now,
		// but need to document these requirements fully for dual-stack setups.
		raftAddress = net.JoinHostPort(peer.NetworkIPv6.Addr().String(), strconv.Itoa(peer.RaftPort))
	}
	if req.GetAsVoter() {
		log.Info("adding candidate to cluster", slog.String("raft_address", raftAddress))
		if err := s.store.AddVoter(ctx, req.GetId(), raftAddress); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to add candidate: %v", err)
		}
	} else {
		log.Info("adding non-voter to cluster", slog.String("raft_address", raftAddress))
		if err := s.store.AddNonVoter(ctx, req.GetId(), raftAddress); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to add non-voter: %v", err)
		}
	}

	// Start building the response
	resp := &v1.JoinResponse{
		NetworkIpv6: s.ulaPrefix.String(),
		AddressIpv6: peer.NetworkIPv6.String(),
		AddressIpv4: func() string {
			if lease.IsValid() {
				return lease.String()
			}
			return ""
		}(),
	}

	// Build current peers for the new node
	graph := s.peers.Graph()
	adjacencyMap, err := graph.AdjacencyMap()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get adjacency map: %v", err)
	}
	ourDescendants := adjacencyMap[req.GetId()]
	resp.Peers = make([]*v1.WireGuardPeer, 0)
	for descendant, edge := range ourDescendants {
		desc, _ := graph.Vertex(descendant)
		slog.Debug("found descendant", slog.Any("descendant", desc))
		// Determine the preferred wireguard endpoint
		var primaryEndpoint string
		if desc.PrimaryEndpoint != "" {
			for _, endpoint := range desc.WireGuardEndpoints {
				if strings.HasPrefix(endpoint, desc.PrimaryEndpoint) {
					primaryEndpoint = endpoint
					break
				}
			}
		}
		if primaryEndpoint == "" && len(desc.WireGuardEndpoints) > 0 {
			primaryEndpoint = desc.WireGuardEndpoints[0]
		}
		// Each direct child is a wireguard peer
		peer := &v1.WireGuardPeer{
			Id:                 desc.ID,
			PublicKey:          desc.PublicKey.String(),
			ZoneAwarenessId:    desc.ZoneAwarenessID,
			PrimaryEndpoint:    primaryEndpoint,
			WireguardEndpoints: desc.WireGuardEndpoints,
			AddressIpv4: func() string {
				if desc.PrivateIPv4.IsValid() {
					return desc.PrivateIPv4.String()
				}
				return ""
			}(),
			AddressIpv6: func() string {
				if desc.NetworkIPv6.IsValid() {
					return desc.NetworkIPv6.String()
				}
				return ""
			}(),
			AllowedIps: make([]string, 0),
		}
		if desc.PrivateIPv4.IsValid() {
			peer.AllowedIps = append(peer.AllowedIps, desc.PrivateIPv4.String())
		}
		if desc.NetworkIPv6.IsValid() {
			peer.AllowedIps = append(peer.AllowedIps, desc.NetworkIPv6.String())
		}
		descTargets := adjacencyMap[edge.Target]
		if len(descTargets) > 0 {
			for descTarget := range descTargets {
				if _, ok := ourDescendants[descTarget]; !ok && descTarget != req.GetId() {
					target, _ := graph.Vertex(descTarget)
					if target.PrivateIPv4.IsValid() {
						peer.AllowedIps = append(peer.AllowedIps, target.PrivateIPv4.String())
					}
					if target.NetworkIPv6.IsValid() {
						peer.AllowedIps = append(peer.AllowedIps, target.NetworkIPv6.String())
					}
				}
			}
		}
		resp.Peers = append(resp.Peers, peer)
	}
	slog.Debug("sending join response", slog.Any("response", resp))
	return resp, nil
}
