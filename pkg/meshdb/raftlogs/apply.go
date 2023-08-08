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

// Package raftlogs provides facilities for applying raft logs to a database.
// It also contains helpers for executing queries and statements provided as
// protobuf messages.
package raftlogs

import (
	"fmt"
	"log/slog"
	"time"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// Apply applies a raft log to the given storage.
func Apply(ctx context.Context, db storage.Storage, logEntry *v1.RaftLogEntry) *v1.RaftApplyResponse {
	start := time.Now()
	log := context.LoggerFrom(ctx)
	switch logEntry.GetType() {
	case v1.RaftCommandType_PUT:
		log.Debug("applying put",
			slog.String("key", logEntry.GetKey()),
			slog.String("value", logEntry.GetValue()),
		)
		err := db.Put(ctx, logEntry.GetKey(), logEntry.GetValue(), logEntry.Ttl.AsDuration())
		res := &v1.RaftApplyResponse{}
		if err != nil {
			res.Error = err.Error()
		}
		res.Time = time.Since(start).String()
		return res
	case v1.RaftCommandType_DELETE:
		log.Debug("applying delete",
			slog.String("key", logEntry.GetKey()),
		)
		err := db.Delete(ctx, logEntry.GetKey())
		res := &v1.RaftApplyResponse{}
		if err != nil {
			res.Error = err.Error()
		}
		res.Time = time.Since(start).String()
		return res
	default:
		return &v1.RaftApplyResponse{
			Error: fmt.Sprintf("unknown command type: %v", logEntry.GetType()),
		}
	}
}
