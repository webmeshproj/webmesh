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
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// Ensure we satisfy the MeshStorage interface.
var _ storage.MeshStorage = &RaftStorage{}

// RaftStorage wraps the storage.Storage interface to force write operations through the Raft log.
type RaftStorage struct {
	storage    storage.MeshStorage
	writecount atomic.Int32
	raft       *Provider
}

// Close closes the storage.
func (rs *RaftStorage) Close() error {
	if !rs.raft.started.Load() {
		return errors.ErrClosed
	}
	return rs.storage.Close()
}

// GetValue gets the value of a key.
func (rs *RaftStorage) GetValue(ctx context.Context, key []byte) ([]byte, error) {
	if !rs.raft.started.Load() {
		return nil, errors.ErrClosed
	}
	if !types.IsValidPathID(string(key)) {
		return nil, errors.ErrInvalidKey
	}
	return rs.storage.GetValue(ctx, key)
}

// ListKeys returns a list of keys.
func (rs *RaftStorage) ListKeys(ctx context.Context, prefix []byte) ([][]byte, error) {
	if !rs.raft.started.Load() {
		return nil, errors.ErrClosed
	}
	return rs.storage.ListKeys(ctx, prefix)
}

// IterPrefix iterates over all keys with a given prefix.
func (rs *RaftStorage) IterPrefix(ctx context.Context, prefix []byte, fn storage.PrefixIterator) error {
	if !rs.raft.started.Load() {
		return errors.ErrClosed
	}
	return rs.storage.IterPrefix(ctx, prefix, fn)
}

// Subscribe subscribes to changes to a prefix.
func (rs *RaftStorage) Subscribe(ctx context.Context, prefix []byte, fn storage.KVSubscribeFunc) (context.CancelFunc, error) {
	if !rs.raft.started.Load() {
		return func() {}, errors.ErrClosed
	}
	return rs.storage.Subscribe(ctx, prefix, fn)
}

// Put sets the value of a key.
func (rs *RaftStorage) PutValue(ctx context.Context, key, value []byte, ttl time.Duration) error {
	if !rs.raft.started.Load() {
		return errors.ErrClosed
	}
	if !types.IsValidPathID(string(key)) {
		return errors.ErrInvalidKey
	}
	if !rs.raft.isVoter() {
		return errors.ErrNotVoter
	}
	logEntry := v1.RaftLogEntry{
		Type:  v1.RaftCommandType_PUT,
		Key:   key,
		Value: value,
		Ttl:   durationpb.New(ttl),
	}
	if rs.raft.Consensus().IsLeader() {
		// lock is taken in the FSM
		return rs.applyLog(ctx, &logEntry)
	}
	// We need to forward the request to the leader.
	return rs.sendLogToLeader(ctx, &logEntry)
}

// Delete removes a key.
func (rs *RaftStorage) Delete(ctx context.Context, key []byte) error {
	if !rs.raft.started.Load() {
		return errors.ErrClosed
	}
	if !types.IsValidPathID(string(key)) {
		return errors.ErrInvalidKey
	}
	if !rs.raft.isVoter() {
		return errors.ErrNotVoter
	}
	logEntry := v1.RaftLogEntry{
		Type: v1.RaftCommandType_DELETE,
		Key:  key,
	}
	if rs.raft.Consensus().IsLeader() {
		// lock is taken in the FSM
		return rs.applyLog(ctx, &logEntry)
	}
	// We need to forward the request to the leader.
	return rs.sendLogToLeader(ctx, &logEntry)
}

func (rs *RaftStorage) sendLogToLeader(ctx context.Context, logEntry *v1.RaftLogEntry) error {
	log := context.LoggerFrom(ctx)
	log.Debug("sending log to leader")
	c, err := rs.raft.Options.Transport.DialLeader(ctx)
	if err != nil {
		return fmt.Errorf("dial leader: %w", err)
	}
	defer c.Close()
	cli := v1.NewMembershipClient(c)
	resp, err := cli.Apply(ctx, logEntry)
	if err != nil {
		return fmt.Errorf("apply log entry: %w", err)
	}
	log.Debug("applied log entry", slog.String("time", resp.GetTime()))
	if resp.GetError() != "" {
		return fmt.Errorf("apply log entry: %s", resp.GetError())
	}
	return nil
}

func (rs *RaftStorage) applyLog(ctx context.Context, logEntry *v1.RaftLogEntry) error {
	rs.writecount.Add(1)
	if rs.writecount.Load() >= rs.raft.Options.BarrierThreshold {
		defer func() {
			rs.writecount.Store(0)
			if err := rs.raft.raft.Barrier(rs.raft.Options.ApplyTimeout).Error(); err != nil {
				rs.raft.log.Warn("Error issuing barrier", "error", err.Error())
			}
		}()
	}
	res, err := rs.raft.ApplyRaftLog(ctx, logEntry)
	if err != nil {
		if errors.Is(err, raft.ErrNotLeader) {
			return errors.ErrNotLeader
		}
		return fmt.Errorf("apply log entry: %w", err)
	}
	if res.GetError() != "" {
		return fmt.Errorf("apply log entry data: %s", res.GetError())
	}
	return nil
}
