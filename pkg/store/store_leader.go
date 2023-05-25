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
	"fmt"

	"github.com/hashicorp/raft"

	"gitlab.com/webmesh/node/pkg/models/raftdb"
)

// IsLeader returns true if this node is the Raft leader.
func (s *store) IsLeader() bool {
	return s.State() == raft.Leader
}

// IsVoter returns true if the current node is a voter in the cluster. If there
// is no reference to the current node in the current cluster configuration then
// false will also be returned.
func (s *store) IsVoter() (bool, error) {
	cfg := s.raft.GetConfiguration()
	if err := cfg.Error(); err != nil {
		return false, err
	}
	for _, srv := range cfg.Configuration().Servers {
		if srv.ID == s.nodeID {
			return srv.Suffrage == raft.Voter, nil
		}
	}
	return false, nil
}

// Leader returns the current Raft leader.
func (s *store) Leader() (raft.ServerID, error) {
	if s.raft == nil || !s.open.Load() {
		return "", ErrNotOpen
	}
	_, id := s.raft.LeaderWithID()
	if id == "" {
		return "", fmt.Errorf("no leader")
	}
	return id, nil
}

// LeaderAddr returns the address of the current leader. Returns a
// blank string if there is no leader or if the Store is not open.
func (s *store) LeaderAddr() (string, error) {
	if !s.open.Load() {
		return "", ErrNotOpen
	}
	addr, _ := s.raft.LeaderWithID()
	return string(addr), nil
}

// LeaderRPCAddr returns the gRPC address of the current leader.
func (s *store) LeaderRPCAddr(ctx context.Context) (string, error) {
	leader, err := s.Leader()
	if err != nil {
		return "", err
	}
	addr, err := raftdb.New(s.ReadDB()).GetNodePrivateRPCAddress(ctx, string(leader))
	if err != nil {
		return "", err
	}
	return addr.(string), nil
}

// Stepdown forces this node to relinquish leadership to another node in
// the cluster. If wait is true then this method will block until the
// leadership transfer is complete and return any error that ocurred.
func (s *store) Stepdown(wait bool) error {
	if !s.open.Load() {
		return ErrNotOpen
	}
	if !s.IsLeader() {
		return ErrNotLeader
	}
	f := s.raft.LeadershipTransfer()
	if !wait {
		return nil
	}
	return f.Error()
}
