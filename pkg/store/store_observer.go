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

package store

import (
	"context"
	"net/netip"
	"reflect"
	"strings"
	"time"

	"github.com/hashicorp/raft"
	"golang.org/x/exp/slog"

	"gitlab.com/webmesh/node/pkg/db/raftdb"
	"gitlab.com/webmesh/node/pkg/wireguard"
)

func (s *store) observe() (closeCh, doneCh chan struct{}) {
	closeCh = make(chan struct{})
	doneCh = make(chan struct{})
	go func() {
		defer close(doneCh)
		for {
			select {
			case <-closeCh:
				return
			case ev := <-s.observerChan:
				s.log.Debug("received observation event",
					slog.String("type", reflect.TypeOf(ev.Data).String()))
				switch data := ev.Data.(type) {
				case raft.RequestVoteRequest:
					s.log.Debug("RequestVoteRequest", slog.Any("data", data))
				case raft.RaftState:
					s.log.Debug("RaftState", slog.String("data", data.String()))
				case raft.PeerObservation:
					s.log.Debug("PeerObservation", slog.Any("data", data))
					s.handlePeerObservation(data)
				case raft.LeaderObservation:
					s.log.Debug("LeaderObservation", slog.Any("data", data))
				case raft.ResumedHeartbeatObservation:
					s.log.Debug("ResumedHeartbeatObservation", slog.Any("data", data))
				case raft.FailedHeartbeatObservation:
					s.log.Debug("FailedHeartbeatObservation", slog.Any("data", data))
					// This is our chance to check if the wireguard key changed, assuming its propogated
					// to our node.
					s.handlePeerObservation(data)
				}
			}
		}
	}()
	return closeCh, doneCh
}

func (s *store) handlePeerObservation(change any) {
	if s.wg == nil {
		return
	}
	// TODO: make configurable
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()

	var peerID string
	var isRemoved bool
	switch ev := change.(type) {
	case raft.PeerObservation:
		s.log.Info("handling peer observation", slog.Any("change", change))
		peerID = string(ev.Peer.ID)
		isRemoved = ev.Removed
	case raft.FailedHeartbeatObservation:
		// These are noisy
		peerID = string(ev.PeerID)
	default:
		s.log.Warn("handlePeerObservation called with unknown type", slog.String("type", reflect.TypeOf(change).String()))
	}

	if isRemoved {
		// Remove the peer from the wireguard interface.
		if err := s.wg.DeletePeer(ctx, &wireguard.Peer{ID: peerID}); err != nil {
			s.log.Error("wireguard remove peer", slog.String("error", err.Error()))
		}
		return
	}

	// Take this opportunity to verify all peer details are correct.
	peers, err := raftdb.New(s.WeakDB()).ListNodePeers(ctx, string(s.nodeID))
	if err != nil {
		s.log.Error("list node peers", slog.String("error", err.Error()))
		return
	}
	for _, peer := range peers {
		var privateIPv4 netip.Prefix
		var privateIPv6 netip.Prefix
		if peer.PrivateAddressV4 != "" && !s.opts.NoIPv4 {
			privateIPv4, err = netip.ParsePrefix(peer.PrivateAddressV4)
			if err != nil {
				s.log.Error("parse private ipv4", slog.String("error", err.Error()))
				return
			}
		}
		if peer.NetworkIpv6.Valid && !s.opts.NoIPv6 {
			privateIPv6, err = netip.ParsePrefix(peer.NetworkIpv6.String)
			if err != nil {
				s.log.Error("parse private ipv6", slog.String("error", err.Error()))
				return
			}
		}
		wgpeer := wireguard.Peer{
			ID:        peer.ID,
			PublicKey: peer.PublicKey.String,
			Endpoint:  peer.Endpoint.String,
			AllowedIPs: func() []string {
				if peer.AllowedIps.Valid {
					return strings.Split(peer.AllowedIps.String, ",")
				}
				return nil
			}(),
			PrivateIPv4: privateIPv4,
			PrivateIPv6: privateIPv6,
		}
		s.log.Info("configuring wireguard peer", slog.Any("peer", wgpeer))
		if err := s.wg.PutPeer(ctx, &wgpeer); err != nil {
			s.log.Error("wireguard put peer", slog.String("error", err.Error()))
			return
		}
	}
}
