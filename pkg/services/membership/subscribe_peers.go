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
	"slices"
	"sync"
	"time"

	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshnet"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

func (s *Server) SubscribePeers(req *v1.SubscribePeersRequest, stream v1.Membership_SubscribePeersServer) error {
	if !context.IsInNetwork(stream.Context(), s.meshnet) {
		addr, _ := context.PeerAddrFrom(stream.Context())
		s.log.Warn("Received SubscribePeers request from out of network", slog.String("peer", addr.String()))
		return status.Errorf(codes.PermissionDenied, "request is not in-network")
	}
	// Validate inputs
	if req.GetId() == "" {
		return status.Error(codes.InvalidArgument, "node id required")
	} else if !types.IsValidNodeID(req.GetId()) {
		return status.Error(codes.InvalidArgument, "node id is invalid")
	}
	if s.plugins.HasAuth() {
		// If we are running with authorization, ensure the node id matches the authenticated caller.
		if !nodeIDMatchesContext(stream.Context(), req.GetId()) {
			return status.Errorf(codes.PermissionDenied, "node id %s does not match authenticated caller", req.GetId())
		}
	}

	peerID := types.NodeID(req.GetId())
	log := s.log.With("remote-peer", peerID)
	ctx := stream.Context()
	db := s.storage.MeshDB()

	log.Debug("Received subscribe peers request for peer", slog.String("peer", peerID.String()))

	var lastIceServers []string
	var lastDnsServers []string
	var lastConfig []*v1.WireGuardPeer

	var notifymu sync.Mutex
	notify := func([]types.MeshNode) {
		log.Debug("Checking for wireguard peers changes for remote peer")
		notifymu.Lock()
		defer notifymu.Unlock()
		iceNegServers, err := listICEServers(ctx, db, peerID)
		if err != nil {
			log.Error("failed to get ice negotiation servers", "error", err.Error())
			return
		}
		dnsServers, err := listDNSServers(ctx, db, peerID)
		if err != nil {
			log.Error("failed to get mdns servers", "error", err.Error())
			return
		}
		peers, err := meshnet.WireGuardPeersFor(ctx, db, peerID)
		if err != nil {
			log.Error("failed to get wireguard peers", "error", err.Error())
			return
		}
		slices.Sort(iceNegServers)
		slices.Sort(dnsServers)
		if len(lastConfig) > 0 {
			if slices.Equal(lastIceServers, iceNegServers) && slices.Equal(lastDnsServers, dnsServers) && types.WireGuardPeersEqual(lastConfig, peers) {
				log.Debug("Skipping wireguard peers notification, no changes")
				return
			}
		}
		lastConfig = peers
		lastIceServers = iceNegServers
		lastDnsServers = dnsServers
		config := &v1.PeerConfigurations{
			Peers:      peers,
			IceServers: iceNegServers,
			DnsServers: dnsServers,
		}
		log.Debug("Sending wireguard peers", "peers", config)
		err = stream.Send(config)
		if err != nil {
			log.Error("Failed to send wireguard peers", "error", err.Error())
			return
		}
	}

	subCancel, err := s.storage.MeshDB().Peers().Subscribe(ctx, notify)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to subscribe to node changes: %v", err)
	}
	defer subCancel()

	t := time.NewTicker(time.Second * 5)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			notify(nil)
		}
	}
}

func listDNSServers(ctx context.Context, st storage.MeshDB, peerID types.NodeID) ([]string, error) {
	var servers []string
	dnsServers, err := st.Peers().List(ctx, storage.FilterByFeature(v1.Feature_MESH_DNS))
	if err != nil {
		return nil, err
	}
	for _, peer := range dnsServers {
		if peer.NodeID() == peerID {
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

func listICEServers(ctx context.Context, st storage.MeshDB, peerID types.NodeID) ([]string, error) {
	var servers []string
	iceServers, err := st.Peers().List(ctx, storage.FilterByFeature(v1.Feature_ICE_NEGOTIATION))
	if err != nil {
		return nil, err
	}
	for _, peer := range iceServers {
		if peer.NodeID() == peerID {
			continue
		}
		if peer.PublicRPCAddr().IsValid() {
			servers = append(servers, peer.PublicRPCAddr().String())
		}
	}
	return servers, nil
}
