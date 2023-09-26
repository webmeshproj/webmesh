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

package raftstorage

import (
	"errors"
	"time"

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// Ensure we satisfy the Consensus interface.
var _ storage.Consensus = &Consensus{}

// RaftConsensus is the Raft consensus implementation.
type Consensus struct {
	*Provider
}

// IsLeader returns true if the Raft node is the leader.
func (r *Consensus) IsLeader() bool {
	return r.raft.State() == raft.Leader
}

// IsMember returns true if the Raft node is a member of the cluster.
func (r *Consensus) IsMember() bool {
	// Non raft-members use the passthrough storage.
	return true
}

// GetPeers returns the peers of the cluster.
func (r *Consensus) GetPeers(ctx context.Context) ([]*v1.StoragePeer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.started.Load() {
		return nil, storage.ErrClosed
	}
	cfg := r.GetRaftConfiguration()
	leader, err := r.GetLeader(ctx)
	if err != nil {
		return nil, err
	}
	peers := make([]*v1.StoragePeer, 0, len(cfg.Servers))
	for _, srv := range cfg.Servers {
		peers = append(peers, &v1.StoragePeer{
			Id:      string(srv.ID),
			Address: string(srv.Address),
			ClusterStatus: func() v1.ClusterStatus {
				if leader.GetId() == string(srv.ID) {
					return v1.ClusterStatus_CLUSTER_LEADER
				}
				switch srv.Suffrage {
				case raft.Voter:
					return v1.ClusterStatus_CLUSTER_VOTER
				case raft.Nonvoter:
					return v1.ClusterStatus_CLUSTER_OBSERVER
				default:
					return v1.ClusterStatus_CLUSTER_NODE
				}
			}(),
		})
	}
	return peers, nil
}

// GetLeader returns the leader of the cluster.
func (r *Consensus) GetLeader(ctx context.Context) (*v1.StoragePeer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.started.Load() {
		return nil, storage.ErrClosed
	}
	if r.IsLeader() {
		// Fast path for leader.
		return &v1.StoragePeer{
			Id:            string(r.nodeID),
			Address:       string(r.Options.Transport.LocalAddr()),
			ClusterStatus: v1.ClusterStatus_CLUSTER_LEADER,
		}, nil
	}
	// Slow path for non-leaders.
	leaderAddr, leaderID := r.raft.LeaderWithID()
	if leaderAddr == "" && leaderID == "" {
		return nil, storage.ErrNoLeader
	}
	return &v1.StoragePeer{
		Id:            string(leaderID),
		Address:       string(leaderAddr),
		ClusterStatus: v1.ClusterStatus_CLUSTER_LEADER,
	}, nil
}

// AddVoter adds a voter to the consensus group.
func (r *Consensus) AddVoter(ctx context.Context, peer *v1.StoragePeer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started.Load() {
		return storage.ErrClosed
	}
	if !r.IsLeader() {
		return storage.ErrNotLeader
	}
	defer func() {
		err := r.raft.Barrier(r.Options.ApplyTimeout).Error()
		if err != nil {
			r.log.Warn("Error issuing barrier", "error", err.Error())
		}
	}()
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	f := r.raft.AddVoter(raft.ServerID(peer.GetId()), raft.ServerAddress(peer.GetAddress()), 0, timeout)
	err := f.Error()
	if err != nil && errors.Is(err, raft.ErrNotLeader) {
		return storage.ErrNotLeader
	}
	return err
}

// AddObserver adds an observer to the consensus group.
func (r *Consensus) AddObserver(ctx context.Context, peer *v1.StoragePeer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started.Load() {
		return storage.ErrClosed
	}
	if !r.IsLeader() {
		return storage.ErrNotLeader
	}
	defer func() {
		err := r.raft.Barrier(r.Options.ApplyTimeout).Error()
		if err != nil {
			r.log.Warn("Error issuing barrier", "error", err.Error())
		}
	}()
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	f := r.raft.AddNonvoter(raft.ServerID(peer.GetId()), raft.ServerAddress(peer.GetAddress()), 0, timeout)
	err := f.Error()
	if err != nil && errors.Is(err, raft.ErrNotLeader) {
		return storage.ErrNotLeader
	}
	return err
}

// DemoteVoter demotes a voter to an observer.
func (r *Consensus) DemoteVoter(ctx context.Context, peer *v1.StoragePeer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started.Load() {
		return storage.ErrClosed
	}
	if !r.IsLeader() {
		return storage.ErrNotLeader
	}
	defer func() {
		err := r.raft.Barrier(r.Options.ApplyTimeout).Error()
		if err != nil {
			r.log.Warn("Error issuing barrier", "error", err.Error())
		}
	}()
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	f := r.raft.DemoteVoter(raft.ServerID(peer.GetId()), 0, timeout)
	err := f.Error()
	if err != nil && errors.Is(err, raft.ErrNotLeader) {
		return storage.ErrNotLeader
	}
	return err
}

// RemovePeer removes a peer from the consensus group.
func (r *Consensus) RemovePeer(ctx context.Context, peer *v1.StoragePeer, wait bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started.Load() {
		return storage.ErrClosed
	}
	if !r.IsLeader() {
		return storage.ErrNotLeader
	}
	defer func() {
		err := r.raft.Barrier(r.Options.ApplyTimeout).Error()
		if err != nil {
			r.log.Warn("Error issuing barrier", "error", err.Error())
		}
	}()
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	f := r.raft.RemoveServer(raft.ServerID(peer.GetId()), 0, timeout)
	if !wait {
		return nil
	}
	err := f.Error()
	if err != nil && errors.Is(err, raft.ErrNotLeader) {
		return storage.ErrNotLeader
	}
	return err
}
