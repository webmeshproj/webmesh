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

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang/snappy"
	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/proto"

	"github.com/webmeshproj/node/pkg/storage"
)

// raftStorage wraps the storage.Storage interface to force write operations through the Raft log.
type raftStorage struct {
	storage.Storage
	store *store
}

// Put sets the value of a key.
func (r *raftStorage) Put(ctx context.Context, key, value string) error {
	logEntry := &v1.RaftLogEntry{
		Type:  v1.RaftCommandType_PUT,
		Key:   key,
		Value: value,
	}
	return r.sendLog(ctx, logEntry)
}

// Delete removes a key.
func (r *raftStorage) Delete(ctx context.Context, key string) error {
	logEntry := &v1.RaftLogEntry{
		Type: v1.RaftCommandType_DELETE,
		Key:  key,
	}
	return r.sendLog(ctx, logEntry)
}

func (r *raftStorage) sendLog(ctx context.Context, logEntry *v1.RaftLogEntry) error {
	timeout := r.store.opts.Raft.ApplyTimeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	data, err := marshalLogEntry(logEntry)
	if err != nil {
		return fmt.Errorf("marshal log entry: %w", err)
	}
	f := r.store.raft.Apply(data, timeout)
	if err := f.Error(); err != nil {
		if errors.Is(err, raft.ErrNotLeader) {
			return ErrNotLeader
		}
		return fmt.Errorf("apply log entry: %w", err)
	}
	resp := f.Response().(*v1.RaftApplyResponse)
	if resp.GetError() != "" {
		return fmt.Errorf("apply log entry data: %s", resp.GetError())
	}
	return nil
}

func marshalLogEntry(logEntry *v1.RaftLogEntry) ([]byte, error) {
	data, err := proto.Marshal(logEntry)
	if err == nil {
		data = snappy.Encode(nil, data)
	}
	if err != nil {
		return nil, fmt.Errorf("encode log entry: %w", err)
	}
	return data, nil
}
