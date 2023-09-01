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
	"sync"
	"time"

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
	if !context.IsInNetwork(stream.Context(), s.wg) {
		addr, _ := context.PeerAddrFrom(stream.Context())
		s.log.Warn("Received SubscribePeers request from out of network", slog.String("peer", addr.String()))
		return status.Errorf(codes.PermissionDenied, "request is not in-network")
	}
	// Validate inputs
	if req.GetId() == "" {
		return status.Error(codes.InvalidArgument, "node id required")
	} else if !peers.IsValidID(req.GetId()) {
		return status.Error(codes.InvalidArgument, "node id is invalid")
	}
	if s.rbac.IsSecure() {
		// If we are running with authorization, ensure the node id matches the authenticated caller.
		if !nodeIDMatchesContext(stream.Context(), req.GetId()) {
			return status.Errorf(codes.PermissionDenied, "node id %s does not match authenticated caller", req.GetId())
		}
	}

	peerID := req.GetId()
	log := s.log.With("remote-peer", peerID)
	ctx := stream.Context()
	st := s.raft.Storage()

	log.Info("Received subscribe peers request")

	var lastIceServers []string
	var lastDnsServers []string
	var lastConfig []*v1.WireGuardPeer

	var notifymu sync.Mutex
	notify := func(_, _ string) {
		log.Debug("Checking for wireguard peers changes for remote peer")
		notifymu.Lock()
		defer notifymu.Unlock()
		iceNegServers, err := listICEServers(ctx, st, peerID)
		if err != nil {
			log.Error("failed to get ice negotiation servers", "error", err.Error())
			return
		}
		dnsServers, err := listDNSServers(ctx, st, peerID)
		if err != nil {
			log.Error("failed to get mdns servers", "error", err.Error())
			return
		}
		peers, err := mesh.WireGuardPeersFor(ctx, st, peerID)
		if err != nil {
			log.Error("failed to get wireguard peers", "error", err.Error())
			return
		}
		slices.Sort(iceNegServers)
		slices.Sort(dnsServers)
		if len(lastConfig) > 0 {
			if slices.Equal(lastIceServers, iceNegServers) && slices.Equal(lastDnsServers, dnsServers) && mesh.WireGuardPeersEqual(lastConfig, peers) {
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

	t := time.NewTicker(time.Second * 5)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			notify("", "")
		}
	}
}

func listDNSServers(ctx context.Context, st storage.MeshStorage, peerID string) ([]string, error) {
	var servers []string
	dnsServers, err := peers.New(st).ListByFeature(ctx, v1.Feature_MESH_DNS)
	if err != nil {
		return nil, err
	}
	for _, peer := range dnsServers {
		if peer.GetId() == peerID {
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
		if peer.GetId() == peerID {
			continue
		}
		if peer.PublicRPCAddr().IsValid() {
			servers = append(servers, peer.PublicRPCAddr().String())
		}
	}
	return servers, nil
}
