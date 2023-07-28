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
	"time"

	"github.com/hashicorp/raft"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// AddNonVoter adds a non-voting node to the cluster.
func (r *raftNode) AddNonVoter(ctx context.Context, id string, addr string) error {
	if r.raft.State() != raft.Leader {
		return ErrNotLeader
	}
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	f := r.raft.AddNonvoter(raft.ServerID(id), raft.ServerAddress(addr), 0, timeout)
	err := f.Error()
	if err != nil && err == raft.ErrNotLeader {
		return ErrNotLeader
	}
	return err
}

// AddVoter adds a voting node to the cluster.
func (r *raftNode) AddVoter(ctx context.Context, id string, addr string) error {
	if r.raft.State() != raft.Leader {
		return ErrNotLeader
	}
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	f := r.raft.AddVoter(raft.ServerID(id), raft.ServerAddress(addr), 0, timeout)
	err := f.Error()
	if err != nil && err == raft.ErrNotLeader {
		return ErrNotLeader
	}
	return err
}

// DemoteVoter demotes a voting node to a non-voting node.
func (r *raftNode) DemoteVoter(ctx context.Context, id string) error {
	if r.raft.State() != raft.Leader {
		return ErrNotLeader
	}
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	f := r.raft.DemoteVoter(raft.ServerID(id), 0, timeout)
	err := f.Error()
	if err != nil && err == raft.ErrNotLeader {
		return ErrNotLeader
	}
	return err
}

// RemoveServer removes a node from the cluster.
func (r *raftNode) RemoveServer(ctx context.Context, id string, wait bool) error {
	if r.raft.State() != raft.Leader {
		return ErrNotLeader
	}
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	f := r.raft.RemoveServer(raft.ServerID(id), 0, timeout)
	if !wait {
		return nil
	}
	err := f.Error()
	if err != nil && err == raft.ErrNotLeader {
		return ErrNotLeader
	}
	return err
}
