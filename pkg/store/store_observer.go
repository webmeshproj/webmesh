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
					if data.Removed {
						// Remove the peer from the wireguard interface.
						if err := s.wg.DeletePeer(ctx, &wireguard.Peer{ID: string(data.Peer.ID)}); err != nil {
							s.log.Error("wireguard remove peer", slog.String("error", err.Error()))
						}
						return
					}
					if err := s.RefreshWireguardPeers(ctx); err != nil {
						s.log.Error("wireguard refresh peers", slog.String("error", err.Error()))
					}
				case raft.LeaderObservation:
					s.log.Debug("LeaderObservation", slog.Any("data", data))
					if err := s.RefreshWireguardPeers(ctx); err != nil {
						s.log.Error("wireguard refresh peers", slog.String("error", err.Error()))
					}
				case raft.ResumedHeartbeatObservation:
					s.log.Debug("ResumedHeartbeatObservation", slog.Any("data", data))
				case raft.FailedHeartbeatObservation:
					s.log.Debug("FailedHeartbeatObservation", slog.Any("data", data))
					if err := s.RefreshWireguardPeers(ctx); err != nil {
						s.log.Error("wireguard refresh peers", slog.String("error", err.Error()))
					}
				}
			}
		}
	}()
	return closeCh, doneCh
}
