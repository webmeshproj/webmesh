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
	"errors"
	"io"
	"time"

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// ErrNotRaftMember is returned for methods that are only valid on raft members.
var ErrNotRaftMember = errors.New("not a raft member")

// NewPassthrough creates a new raft instance that is a no-op for most methods
// and uses the given Dialer for storage connections.
func NewPassthrough(dialer NodeDialer) Raft {
	return &passthroughRaft{dialer}
}

// passthroughRaft implements the raft interface, but is a no-op for most methods.
// It is used by non-raft members to allow them to expose the raft interface.
// It should later be removed in favor of less coupling between the connection
// and raft interfaces.
type passthroughRaft struct {
	dialer NodeDialer
}

func (p *passthroughRaft) Start(ctx context.Context, opts *StartOptions) error {
	return nil
}

func (p *passthroughRaft) Bootstrap(ctx context.Context, opts *BootstrapOptions) error {
	return ErrNotRaftMember
}

func (p *passthroughRaft) Storage() storage.Storage {
	// TODO
	return nil
}

func (p *passthroughRaft) Configuration() raft.Configuration {
	return raft.Configuration{}
}

func (p *passthroughRaft) LastIndex() uint64 {
	return 0
}

func (p *passthroughRaft) LastAppliedIndex() uint64 {
	return 0
}

func (p *passthroughRaft) ListenPort() int {
	return 0
}

func (p *passthroughRaft) LeaderID() (string, error) {
	return "", ErrNotRaftMember
}

func (p *passthroughRaft) IsLeader() bool {
	return false
}

func (p *passthroughRaft) IsVoter() bool {
	return false
}

func (p *passthroughRaft) IsObserver() bool {
	return false
}

func (p *passthroughRaft) AddNonVoter(ctx context.Context, id string, addr string) error {
	return ErrNotRaftMember
}

func (p *passthroughRaft) AddVoter(ctx context.Context, id string, addr string) error {
	return ErrNotRaftMember
}

func (p *passthroughRaft) DemoteVoter(ctx context.Context, id string) error {
	return ErrNotRaftMember
}

func (p *passthroughRaft) RemoveServer(ctx context.Context, id string, wait bool) error {
	return ErrNotRaftMember
}

func (p *passthroughRaft) Apply(ctx context.Context, log *v1.RaftLogEntry) (*v1.RaftApplyResponse, error) {
	return nil, ErrNotRaftMember
}

func (p *passthroughRaft) Snapshot() (*raft.SnapshotMeta, io.ReadCloser, error) {
	return nil, nil, ErrNotRaftMember
}

func (p *passthroughRaft) Barrier(ctx context.Context, timeout time.Duration) (took time.Duration, err error) {
	return 0, ErrNotRaftMember
}

func (p *passthroughRaft) Stop(ctx context.Context) error {
	return nil
}
