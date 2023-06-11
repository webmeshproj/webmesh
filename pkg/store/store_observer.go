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
	"reflect"

	"github.com/hashicorp/raft"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/node/pkg/meshdb/peers"
)

func (s *store) observe() (closeCh, doneCh chan struct{}) {
	closeCh = make(chan struct{})
	doneCh = make(chan struct{})
	failedHeartbeats := make(map[raft.ServerID]int)
	go func() {
		defer close(doneCh)
		for {
			select {
			case <-closeCh:
				s.log.Debug("stopping raft observer")
				return
			case ev := <-s.observerChan:
				s.log.Debug("received observation event", slog.String("type", reflect.TypeOf(ev.Data).String()))
				ctx := context.Background()
				switch data := ev.Data.(type) {
				case raft.RequestVoteRequest:
					s.log.Debug("RequestVoteRequest", slog.Any("data", data))
				case raft.RaftState:
					s.log.Debug("RaftState", slog.String("data", data.String()))
				case raft.PeerObservation:
					s.log.Debug("PeerObservation", slog.Any("data", data))
					if s.noWG {
						continue
					}
					if err := s.refreshWireguardPeers(ctx); err != nil {
						s.log.Error("wireguard refresh peers", slog.String("error", err.Error()))
					}
				case raft.LeaderObservation:
					s.log.Debug("LeaderObservation", slog.Any("data", data))
				case raft.ResumedHeartbeatObservation:
					s.log.Debug("ResumedHeartbeatObservation", slog.Any("data", data))
				case raft.FailedHeartbeatObservation:
					s.log.Debug("FailedHeartbeatObservation", slog.Any("data", data))
					if failedHeartbeats[data.PeerID] > 10 {
						s.log.Error("failed heartbeat", slog.String("peer", string(data.PeerID)))
						// If the peer is a non voter then we can remove it from the cluster
						// and it will be re-added when it comes back online.
						cfg := s.raft.GetConfiguration().Configuration()
						if s.IsLeader() {
							for _, srv := range cfg.Servers {
								if srv.ID == data.PeerID && srv.Suffrage == raft.Nonvoter {
									s.log.Info("removing non-voting peer from cluster", slog.String("peer", string(data.PeerID)))
									if err := s.RemoveServer(ctx, string(data.PeerID), false); err != nil {
										s.log.Error("remove non-voting peer", slog.String("error", err.Error()))
									}
									if err := peers.New(s).Delete(ctx, string(data.PeerID)); err != nil {
										s.log.Error("remove node", slog.String("error", err.Error()))
									}
								}
							}
						}
						delete(failedHeartbeats, data.PeerID)
						continue
					}
					if failedHeartbeats[data.PeerID] == 0 {
						failedHeartbeats[data.PeerID] = 1
					} else {
						failedHeartbeats[data.PeerID]++
					}
				}
			}
		}
	}()
	return closeCh, doneCh
}
