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

package meshnode

import (
	"context"
	"log/slog"
	"reflect"

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/go/v1"

	"github.com/webmeshproj/webmesh/pkg/meshnet"
	"github.com/webmeshproj/webmesh/pkg/storage/providers/raftstorage"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

func (s *meshStore) newObserver() func(context.Context, raft.Observation) {
	failedHeartBeats := make(map[raft.ServerID]int)
	return func(ctx context.Context, ev raft.Observation) {
		log := s.log.With("event", "observation")
		log.Debug("Received observation event", slog.String("type", reflect.TypeOf(ev.Data).String()))
		provider := s.Storage().(*raftstorage.Provider)
		consensus := provider.Consensus()
		switch data := ev.Data.(type) {
		case raft.FailedHeartbeatObservation:
			if s.opts.HeartbeatPurgeThreshold <= 0 {
				return
			}
			failedHeartBeats[data.PeerID]++
			log.Debug("Failed heartbeat", slog.String("peer", string(data.PeerID)), slog.Int("count", failedHeartBeats[data.PeerID]))
			if failedHeartBeats[data.PeerID] >= s.opts.HeartbeatPurgeThreshold && consensus.IsLeader() {
				// Remove the peer from the cluster
				log.Info("Failed heartbeat threshold reached, removing peer", slog.String("peer", string(data.PeerID)))
				if err := consensus.RemovePeer(ctx, types.StoragePeer{StoragePeer: &v1.StoragePeer{Id: string(data.PeerID)}}, true); err != nil {
					log.Warn("Failed to remove peer", slog.String("error", err.Error()))
					return
				}
				if err := provider.MeshDB().Peers().Delete(ctx, types.NodeID(data.PeerID)); err != nil {
					log.Warn("Failed to remove peer from database", slog.String("error", err.Error()))
				}
				delete(failedHeartBeats, data.PeerID)
			}
		case raft.ResumedHeartbeatObservation:
			if s.opts.HeartbeatPurgeThreshold > 0 {
				delete(failedHeartBeats, data.PeerID)
			}
		case raft.PeerObservation:
			if s.testStore {
				return
			}
			if string(data.Peer.ID) == s.nodeID {
				return
			}
			wgpeers, err := meshnet.WireGuardPeersFor(ctx, provider.MeshDB(), s.ID())
			if err != nil {
				log.Warn("Failed to get wireguard peers", slog.String("error", err.Error()))
			} else {
				if err := s.nw.Peers().Refresh(ctx, wgpeers); err != nil {
					log.Warn("Failed to refresh local wireguard peers", slog.String("error", err.Error()))
				}
			}
			if s.plugins.HasWatchers() {
				node, err := provider.MeshDB().Peers().Get(ctx, types.NodeID(data.Peer.ID))
				if err != nil {
					log.Warn("Failed to lookup peer, can't emit event", slog.String("error", err.Error()))
					return
				}
				err = s.plugins.Emit(ctx, &v1.Event{
					Type: func() v1.Event_WatchEvent {
						if data.Removed {
							return v1.Event_NODE_LEAVE
						}
						return v1.Event_NODE_JOIN
					}(),
					Event: &v1.Event_Node{
						Node: node.MeshNode,
					},
				})
				if err != nil {
					log.Warn("Error sending node join/leave event", slog.String("error", err.Error()))
				}
			}
		case raft.LeaderObservation:
			if s.plugins.HasWatchers() {
				node, err := provider.MeshDB().Peers().Get(ctx, types.NodeID(data.LeaderID))
				if err != nil {
					log.Warn("Failed to get leader, may be fresh cluster, can't emit event", slog.String("error", err.Error()))
					return
				}
				err = s.plugins.Emit(ctx, &v1.Event{
					Type: v1.Event_LEADER_CHANGE,
					Event: &v1.Event_Node{
						Node: node.MeshNode,
					},
				})
				if err != nil {
					log.Warn("Error sending leader change event", slog.String("error", err.Error()))
				}
			}
		}
	}
}
