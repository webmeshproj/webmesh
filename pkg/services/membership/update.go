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
	"net/netip"
	"sort"

	"github.com/google/go-cmp/cmp"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/services/rbac"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/storageutil"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

func (s *Server) Update(ctx context.Context, req *v1.UpdateRequest) (*v1.UpdateResponse, error) {
	if !context.IsInNetwork(ctx, s.wg) {
		addr, _ := context.PeerAddrFrom(ctx)
		s.log.Warn("Received Update request from out of network", slog.String("peer", addr.String()))
		return nil, status.Errorf(codes.PermissionDenied, "request is not in-network")
	}
	if !s.storage.Consensus().IsLeader() {
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
	} else if !storageutil.IsValidNodeID(req.GetId()) {
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

	var publicKey crypto.PublicKey
	if req.GetPublicKey() != "" {
		publicKey, err = crypto.DecodePublicKey(req.GetPublicKey())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid public key: %v", err)
		}
	}

	// Check that the node is indeed who they say they are
	if s.rbac.IsSecure() {
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
	}

	// Lookup the peer's current state
	var currentSuffrage v1.ClusterStatus
	var currentAddress string
	storageStatus := s.storage.Status()
	p := s.storage.MeshDB().Peers()
	peer, err := p.Get(ctx, types.NodeID(req.GetId()))
	if err != nil {
		if errors.IsNodeNotFound(err) {
			return nil, status.Errorf(codes.Internal, "failed to lookup peer: %v", err)
		}
		// Peer doesn't exist, they need to call Join first
		return nil, status.Errorf(codes.FailedPrecondition, "node %s not found", req.GetId())
	}
	// Determine the peer's current status
	for _, server := range storageStatus.GetPeers() {
		if server.GetId() == peer.GetId() {
			currentSuffrage = server.GetClusterStatus()
			currentAddress = server.GetAddress()
			break
		}
	}
	// Ensure any new routes
	_, err = s.ensurePeerRoutes(ctx, peer.NodeID(), req.GetRoutes())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to ensure peer routes: %v", err)
	}
	// Overwrite any provided fields
	var hasChanges bool
	toUpdate := peer
	// Check the public key

	if publicKey != nil {
		encoded, err := publicKey.Encode()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to encode public key: %v", err)
		}
		if encoded != peer.PublicKey {
			toUpdate.PublicKey = encoded
			hasChanges = true
		}
	}
	// Check endpoints
	if req.GetPrimaryEndpoint() != "" && req.GetPrimaryEndpoint() != peer.PrimaryEndpoint {
		toUpdate.PrimaryEndpoint = req.GetPrimaryEndpoint()
		hasChanges = true
	}
	if len(req.GetWireguardEndpoints()) > 0 {
		sort.Strings(req.GetWireguardEndpoints())
		sort.Strings(peer.WireguardEndpoints)
		if !cmp.Equal(req.GetWireguardEndpoints(), peer.WireguardEndpoints) {
			toUpdate.WireguardEndpoints = req.GetWireguardEndpoints()
			hasChanges = true
		}
	}
	// Zone awareness
	if req.GetZoneAwarenessID() != "" && req.GetZoneAwarenessID() != peer.GetZoneAwarenessID() {
		toUpdate.ZoneAwarenessID = req.GetZoneAwarenessID()
		hasChanges = true
	}
	// Multiaddrs
	if len(req.GetMultiaddrs()) > 0 {
		sort.Strings(req.GetMultiaddrs())
		sort.Strings(peer.Multiaddrs)
		if !cmp.Equal(req.GetMultiaddrs(), peer.Multiaddrs) {
			toUpdate.Multiaddrs = req.GetMultiaddrs()
			hasChanges = true
		}
	}
	// Features
	if len(req.GetFeatures()) > 0 {
		toUpdate.Features = req.GetFeatures()
		hasChanges = true
	}

	// Apply any node changes
	if hasChanges {
		log.Debug("Updating peer", slog.Any("peer", toUpdate))
		err = p.Put(ctx, toUpdate)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to update peer: %v", err)
		}
	}

	// Change to voter if requested and not already
	if req.GetAsVoter() && currentSuffrage != v1.ClusterStatus_CLUSTER_VOTER {
		if currentAddress == "" {
			return nil, status.Errorf(codes.Internal, "failed to lookup peer address")
		}
		// Promote to voter
		log.Debug("Promoting peer to voter", slog.String("storage-address", string(currentAddress)))
		if err := s.storage.Consensus().AddVoter(ctx, &v1.StoragePeer{
			Id:      req.GetId(),
			Address: currentAddress,
		}); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to promote to voter: %v", err)
		}
	}
	return &v1.UpdateResponse{}, nil
}
