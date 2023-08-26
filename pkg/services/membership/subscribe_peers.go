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
	"sync"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slices"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	"github.com/webmeshproj/webmesh/pkg/net/mesh"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

func (s *Server) SubscribePeers(req *v1.SubscribePeersRequest, stream v1.Membership_SubscribePeersServer) error {
	// Validate inputs
	if req.GetId() == "" {
		return status.Error(codes.InvalidArgument, "node id required")
	} else if !peers.IsValidID(req.GetId()) {
		return status.Error(codes.InvalidArgument, "node id is invalid")
	}
	if !s.insecure {
		// If we are running with authorization, ensure the node id matches the authenticated caller.
		if !nodeIDMatchesContext(stream.Context(), req.GetId()) {
			return status.Errorf(codes.PermissionDenied, "node id %s does not match authenticated caller", req.GetId())
		}
	}

	peerID := req.GetId()
	log := s.log.With("remote-peer", peerID)
	ctx := stream.Context()
	st := s.store.Storage()

	var iceServers []string
	var dnsServers []string
	var lastConfig []*v1.WireGuardPeer

	var notifymu sync.Mutex
	notify := func(_, _ string) {
		notifymu.Lock()
		defer notifymu.Unlock()
		log.Debug("received node change notification")
		mdnsServers, err := listDNSServers(ctx, st, peerID)
		if err != nil {
			log.Error("failed to get mdns servers", "error", err.Error())
			return
		}
		iceNegServers, err := listICEServers(ctx, st, peerID)
		if err != nil {
			log.Error("failed to get ice negotiation servers", "error", err.Error())
			return
		}
		peers, err := mesh.WireGuardPeersFor(ctx, st, peerID)
		if err != nil {
			log.Error("failed to get wireguard peers", "error", err.Error())
			return
		}
		if lastConfig != nil {
			if slices.Equal(lastConfig, peers) && slices.Equal(iceServers, iceNegServers) && slices.Equal(dnsServers, mdnsServers) {
				return
			}
		}
		lastConfig = peers
		iceServers = iceNegServers
		dnsServers = mdnsServers
		config := &v1.PeerConfigurations{
			Peers:      peers,
			IceServers: iceServers,
			DnsServers: dnsServers,
		}
		log.Debug("sending wireguard peers", "peers", config)
		err = stream.Send(config)
		if err != nil {
			log.Error("failed to send wireguard peers", "error", err.Error())
			return
		}
	}

	nodeCancel, err := st.Subscribe(ctx, peers.NodesPrefix, notify)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to subscribe to node changes: %v", err)
	}
	defer nodeCancel()
	edgeCancel, err := st.Subscribe(ctx, peers.EdgesPrefix, notify)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to subscribe to edge changes: %v", err)
	}
	defer edgeCancel()

	<-stream.Context().Done()
	return nil
}

func listDNSServers(ctx context.Context, st storage.MeshStorage, peerID string) ([]string, error) {
	var servers []string
	dnsServers, err := peers.New(st).ListByFeature(ctx, v1.Feature_MESH_DNS)
	if err != nil {
		return nil, err
	}
	for _, peer := range dnsServers {
		if peer.ID == peerID {
			continue
		}
		switch {
		// Prefer the IPv4 address
		case peer.PrivateDNSAddrV4().IsValid():
			servers = append(servers, peer.PrivateDNSAddrV4().String())
		case peer.PrivateDNSAddrV6().IsValid():
			servers = append(servers, peer.PrivateDNSAddrV6().String())
		}
	}
	return servers, nil
}

func listICEServers(ctx context.Context, st storage.MeshStorage, peerID string) ([]string, error) {
	var servers []string
	iceServers, err := peers.New(st).ListByFeature(ctx, v1.Feature_ICE_NEGOTIATION)
	if err != nil {
		return nil, err
	}
	for _, peer := range iceServers {
		if peer.ID == peerID {
			continue
		}
		if peer.PublicRPCAddr().IsValid() {
			servers = append(servers, peer.PublicRPCAddr().String())
		}
	}
	return servers, nil
}
