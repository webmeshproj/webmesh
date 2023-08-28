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
	"errors"
	"log/slog"
	"net/netip"
	"sort"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	"github.com/webmeshproj/webmesh/pkg/services/rbac"
)

func (s *Server) Update(ctx context.Context, req *v1.UpdateRequest) (*v1.UpdateResponse, error) {
	if !s.raft.IsLeader() {
		return nil, status.Errorf(codes.FailedPrecondition, "not leader")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	log := s.log.With("op", "update", "id", req.GetId())
	ctx = context.WithLogger(ctx, log)

	log.Debug("Update request received", slog.Any("request", req))
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
	var publicKey wgtypes.Key
	if req.GetPublicKey() != "" {
		publicKey, err = wgtypes.ParseKey(req.GetPublicKey())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid public key: %v", err)
		}
	}

	// Check that the node is indeed who they say they are
	if !s.insecure {
		if !nodeIDMatchesContext(ctx, req.GetId()) {
			return nil, status.Errorf(codes.PermissionDenied, "node id %s does not match authenticated caller", req.GetId())
		}
		// We can go ahead and check here if the node is allowed to do what they want.
		var actions rbac.Actions
		if req.GetAsVoter() {
			actions = append(actions, canVoteAction)
		}
		if len(req.GetRoutes()) > 0 {
			actions = append(actions, canPutRouteAction)
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
	_, err = s.raft.Barrier(ctx, time.Second*15)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to send barrier: %v", err)
	}

	// Send another barrier after we're done to ensure all nodes are
	// fully caught up before we return
	defer func() {
		_, _ = s.raft.Barrier(ctx, time.Second*15)
	}()

	// Lookup the peer's current state
	var currentSuffrage raft.ServerSuffrage = -1
	var currentAddress raft.ServerAddress = ""
	cfg, err := s.raft.Configuration()
	if err != nil {
		// Should never happen
		return nil, status.Errorf(codes.Internal, "failed to get configuration: %v", err)
	}
	p := peers.New(s.raft.Storage())
	peer, err := p.Get(ctx, req.GetId())
	if err != nil {
		if errors.Is(err, peers.ErrNodeNotFound) {
			return nil, status.Errorf(codes.Internal, "failed to lookup peer: %v", err)
		}
		// Peer doesn't exist, they need to call Join first
		return nil, status.Errorf(codes.FailedPrecondition, "node %s not found", req.GetId())
	}
	// Determine the peer's current status
	for _, server := range cfg.Servers {
		if server.ID == raft.ServerID(peer.ID) {
			currentSuffrage = server.Suffrage
			currentAddress = server.Address
			break
		}
	}
	// Ensure any new routes
	_, err = s.ensurePeerRoutes(ctx, peer.ID, req.GetRoutes())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to ensure peer routes: %v", err)
	}
	// Overwrite any provided fields
	var hasChanges bool
	toUpdate := &peer
	// Check the public key
	if publicKey != (wgtypes.Key{}) && publicKey != peer.PublicKey {
		toUpdate.PublicKey = publicKey
		hasChanges = true
	}
	// Check the raft, grpc, and meshdns ports
	if req.GetRaftPort() != 0 && req.GetRaftPort() != int32(peer.RaftPort) {
		toUpdate.RaftPort = int(req.GetRaftPort())
		hasChanges = true
	}
	if req.GetGrpcPort() != 0 && req.GetGrpcPort() != int32(peer.GRPCPort) {
		toUpdate.GRPCPort = int(req.GetGrpcPort())
		hasChanges = true
	}
	if req.GetMeshdnsPort() != 0 && req.GetMeshdnsPort() != int32(peer.DNSPort) {
		toUpdate.DNSPort = int(req.GetMeshdnsPort())
		hasChanges = true
	}
	// Check endpoints
	if req.GetPrimaryEndpoint() != "" && req.GetPrimaryEndpoint() != peer.PrimaryEndpoint {
		toUpdate.PrimaryEndpoint = req.GetPrimaryEndpoint()
		hasChanges = true
	}
	if len(req.GetWireguardEndpoints()) > 0 {
		sort.Strings(req.GetWireguardEndpoints())
		sort.Strings(peer.WireGuardEndpoints)
		if !cmp.Equal(req.GetWireguardEndpoints(), peer.WireGuardEndpoints) {
			toUpdate.WireGuardEndpoints = req.GetWireguardEndpoints()
			hasChanges = true
		}
	}
	// Zone awareness
	if req.GetZoneAwarenessId() != "" && req.GetZoneAwarenessId() != peer.ZoneAwarenessID {
		toUpdate.ZoneAwarenessID = req.GetZoneAwarenessId()
		hasChanges = true
	}
	// Features
	if len(req.GetFeatures()) > 0 {
		toUpdate.Features = req.GetFeatures()
		hasChanges = true
	}

	// Apply any node changes
	if hasChanges {
		log.Debug("updating peer", slog.Any("peer", toUpdate))
		err = p.Put(ctx, *toUpdate)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to update peer: %v", err)
		}
	}

	// Change to voter if requested and not already
	if req.GetAsVoter() && currentSuffrage != raft.Voter {
		if currentAddress == "" {
			return nil, status.Errorf(codes.Internal, "failed to lookup peer address")
		}
		// Promote to voter
		log.Info("promoting to voter", slog.String("raft_address", string(currentAddress)))
		if err := s.raft.AddVoter(ctx, peer.ID, string(currentAddress)); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to promote to voter: %v", err)
		}
	}
	return &v1.UpdateResponse{}, nil
}
