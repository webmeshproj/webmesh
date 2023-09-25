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

// Package raft contains Raft consensus for WebMesh.
package raft

import (
	"errors"

	"github.com/hashicorp/raft"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

var (
	// ErrStarted is returned when the Raft node is already started.
	ErrStarted = errors.New("raft node already started")
	// ErrClosed is returned when the Raft node is already closed.
	ErrClosed = errors.New("raft node is closed")
	// ErrNoLeader is returned when there is no leader.
	ErrNoLeader = errors.New("no leader")
	// ErrAlreadyBootstrapped is returned when the Raft node is already bootstrapped.
	ErrAlreadyBootstrapped = storage.ErrAlreadyBootstrapped
	// ErrNotLeader is returned when the Raft node is not the leader.
	ErrNotLeader = raft.ErrNotLeader
	// ErrNotVoter is returned when the Raft node is not a voter.
	ErrNotVoter = raft.ErrNotVoter
)

// IsNoLeaderErr returns true if the error is a raft.ErrNoLeader.
func IsNoLeaderErr(err error) bool {
	return errors.Is(err, ErrNoLeader)
}
