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

package raft

import (
	"github.com/hashicorp/raft"
	"golang.org/x/exp/slog"
)

func (r *raftNode) observe() (closeCh, doneCh chan struct{}) {
	closeCh = make(chan struct{})
	doneCh = make(chan struct{})
	go func() {
		defer close(doneCh)
		for {
			select {
			case <-closeCh:
				r.log.Debug("stopping raft observer")
				return
			case ev := <-r.observerChan:
				switch data := ev.Data.(type) {
				case raft.RequestVoteRequest:
					r.log.Debug("RequestVoteRequest", slog.Any("data", data))
				case raft.RaftState:
					r.log.Debug("RaftState", slog.String("data", data.String()))
				case raft.PeerObservation:
					r.log.Debug("PeerObservation", slog.Any("data", data))
				case raft.LeaderObservation:
					r.log.Debug("LeaderObservation", slog.Any("data", data))
				case raft.ResumedHeartbeatObservation:
					r.log.Debug("ResumedHeartbeatObservation", slog.Any("data", data))
				case raft.FailedHeartbeatObservation:
					r.log.Debug("FailedHeartbeatObservation", slog.Any("data", data))
				}
				if r.opts.OnObservation != nil {
					r.opts.OnObservation(ev)
				}
			}
		}
	}()
	return closeCh, doneCh
}
