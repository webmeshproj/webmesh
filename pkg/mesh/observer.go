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

package mesh

import (
	"context"
	"log/slog"
	"reflect"

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	"github.com/webmeshproj/webmesh/pkg/util/meshutil"
)

func (s *meshStore) newObserver() func(context.Context, raft.Observation) {
	failedHeartBeats := make(map[raft.ServerID]int)
	return func(ctx context.Context, ev raft.Observation) {
		log := s.log.With("event", "observation")
		log.Debug("received observation event", slog.String("type", reflect.TypeOf(ev.Data).String()))
		switch data := ev.Data.(type) {
		case raft.FailedHeartbeatObservation:
			if s.opts.HeartbeatPurgeThreshold <= 0 {
				return
			}
			failedHeartBeats[data.PeerID]++
			log.Debug("failed heartbeat", slog.String("peer", string(data.PeerID)), slog.Int("count", failedHeartBeats[data.PeerID]))
			if failedHeartBeats[data.PeerID] >= s.opts.HeartbeatPurgeThreshold && s.raft.IsLeader() {
				// Remove the peer from the cluster
				log.Info("failed heartbeat threshold reached, removing peer", slog.String("peer", string(data.PeerID)))
				if err := s.raft.RemoveServer(ctx, string(data.PeerID), true); err != nil {
					log.Warn("failed to remove peer", slog.String("error", err.Error()))
					return
				}
				if err := peers.New(s.Storage()).Delete(ctx, string(data.PeerID)); err != nil {
					log.Warn("failed to remove peer from database", slog.String("error", err.Error()))
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
			wgpeers, err := meshutil.WireGuardPeersFor(ctx, s.Storage(), s.ID())
			if err != nil {
				log.Warn("failed to get wireguard peers", slog.String("error", err.Error()))
			} else {
				if err := s.nw.Peers().Refresh(ctx, wgpeers); err != nil {
					log.Warn("wireguard refresh peers", slog.String("error", err.Error()))
				}
			}
			if s.plugins.HasWatchers() {
				p := peers.New(s.Storage())
				node, err := p.Get(ctx, string(data.Peer.ID))
				if err != nil {
					log.Warn("failed to lookup peer, can't emit event", slog.String("error", err.Error()))
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
					log.Warn("error sending node join/leave event", slog.String("error", err.Error()))
				}
			}
		case raft.LeaderObservation:
			if s.plugins.HasWatchers() {
				p := peers.New(s.Storage())
				node, err := p.Get(ctx, string(data.LeaderID))
				if err != nil {
					log.Warn("failed to get leader, may be fresh cluster, can't emit event", slog.String("error", err.Error()))
					return
				}
				err = s.plugins.Emit(ctx, &v1.Event{
					Type: v1.Event_LEADER_CHANGE,
					Event: &v1.Event_Node{
						Node: node.MeshNode,
					},
				})
				if err != nil {
					log.Warn("error sending leader change event", slog.String("error", err.Error()))
				}
			}
		}
	}
}
