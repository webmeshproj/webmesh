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
	"fmt"
	"io"
	"time"

	"github.com/golang/snappy"
	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/meshdb/models"
	"github.com/webmeshproj/node/pkg/meshdb/networking"
	"github.com/webmeshproj/node/pkg/meshdb/raftlogs"
)

// Snapshot returns a Raft snapshot.
func (s *store) Snapshot() (raft.FSMSnapshot, error) {
	s.dataMux.Lock()
	defer s.dataMux.Unlock()
	return s.snapshotter.Snapshot(context.Background())
}

// Restore restores a Raft snapshot.
func (s *store) Restore(r io.ReadCloser) error {
	s.dataMux.Lock()
	defer s.dataMux.Unlock()
	return s.snapshotter.Restore(context.Background(), r)
}

// ApplyBatch implements the raft.BatchingFSM interface.
func (s *store) ApplyBatch(logs []*raft.Log) []any {
	s.dataMux.Lock()
	defer s.dataMux.Unlock()
	s.log.Debug("applying batch", slog.Int("count", len(logs)))
	res := make([]any, len(logs))
	var edgeChange bool
	var routeChange bool
	for i, l := range logs {
		var edgeChanged, routeChanged bool
		edgeChanged, routeChanged, res[i] = s.applyLog(l)
		if edgeChanged {
			edgeChange = true
		}
		if routeChanged {
			routeChange = true
		}
	}
	if (edgeChange || routeChange) && s.wg != nil {
		if s.raft.AppliedIndex() == s.lastAppliedIndex.Load() {
			go func() {
				if s.noWG {
					return
				}
				s.log.Debug("applied batch with node edge changes, refreshing wireguard peers")
				if err := s.refreshWireguardPeers(context.Background()); err != nil {
					s.log.Error("refresh wireguard peers failed", slog.String("error", err.Error()))
				}
			}()
		}
	}
	if routeChange && s.wg != nil {
		if s.raft.AppliedIndex() == s.lastAppliedIndex.Load() {
			go func() {
				if s.noWG {
					return
				}
				ctx := context.Background()
				nw := networking.New(s.DB())
				routes, err := nw.GetRoutesByNode(ctx, s.ID())
				if err != nil {
					s.log.Error("error getting routes by node", slog.String("error", err.Error()))
					return
				}
				if len(routes) > 0 {
					s.log.Debug("applied node route change, ensuring masquerade rules are in place")
					if !s.masquerading {
						s.wgmux.Lock()
						defer s.wgmux.Unlock()
						err = s.fw.AddMasquerade(ctx, s.wg.Name())
						if err != nil {
							s.log.Error("error adding masquerade rule", slog.String("error", err.Error()))
						} else {
							s.masquerading = true
						}
					}
				}
			}()
		}
	}
	return res
}

// Apply applies a Raft log entry to the store.
func (s *store) Apply(l *raft.Log) any {
	s.dataMux.Lock()
	defer s.dataMux.Unlock()
	edgeChange, routeChange, res := s.applyLog(l)
	if (edgeChange || routeChange) && s.wg != nil {
		if s.raft.AppliedIndex() == s.lastAppliedIndex.Load() {
			go func() {
				if s.noWG {
					return
				}
				s.log.Debug("applied node edge change, refreshing wireguard peers")
				if err := s.refreshWireguardPeers(context.Background()); err != nil {
					s.log.Error("refresh wireguard peers failed", slog.String("error", err.Error()))
				}
			}()
		}
	}
	if routeChange && s.wg != nil {
		if s.raft.AppliedIndex() == s.lastAppliedIndex.Load() {
			go func() {
				if s.noWG {
					return
				}
				ctx := context.Background()
				nw := networking.New(s.DB())
				routes, err := nw.GetRoutesByNode(ctx, s.ID())
				if err != nil {
					s.log.Error("error getting routes by node", slog.String("error", err.Error()))
					return
				}
				if len(routes) > 0 {
					s.log.Debug("applied node route change, ensuring masquerade rules are in place")
					if !s.masquerading {
						s.wgmux.Lock()
						defer s.wgmux.Unlock()
						err = s.fw.AddMasquerade(ctx, s.wg.Name())
						if err != nil {
							s.log.Error("error adding masquerade rule", slog.String("error", err.Error()))
						} else {
							s.masquerading = true
						}
					}
				}
			}()
		}
	}
	return res
}

func (s *store) applyLog(l *raft.Log) (edgeChange, routeChange bool, res any) {
	log := s.log.With(slog.Int("index", int(l.Index)), slog.Int("term", int(l.Term)))
	log.Debug("applying log", "type", l.Type.String())

	start := time.Now()
	defer func() {
		log.Debug("finished applying log", slog.String("took", time.Since(start).String()))
	}()
	defer s.lastAppliedIndex.Store(l.Index)
	defer s.currentTerm.Store(l.Term)

	// Validate and store the term/index to the local DB

	dbTerm := s.currentTerm.Load()
	dbIndex := s.lastAppliedIndex.Load()
	log.Debug("last applied index",
		slog.Int("last-term", int(dbTerm)),
		slog.Int("last-index", int(dbIndex)))

	if l.Term < dbTerm {
		log.Debug("received log from old term")
		return false, false, &v1.RaftApplyResponse{
			Time: time.Since(start).String(),
		}
	} else if l.Index <= dbIndex {
		log.Debug("log already applied to database")
		return false, false, &v1.RaftApplyResponse{
			Time: time.Since(start).String(),
		}
	}

	if l.Type != raft.LogCommand {
		// We only care about command logs.
		return false, false, &v1.RaftApplyResponse{
			Time: time.Since(start).String(),
		}
	}

	// Decode the log entry
	var cmd v1.RaftLogEntry
	var err error
	switch s.raftLogFormat {
	case RaftLogFormatJSON:
		err = protojson.Unmarshal(l.Data, &cmd)
	case RaftLogFormatProtobuf:
		err = proto.Unmarshal(l.Data, &cmd)
	case RaftLogFormatProtobufSnappy:
		var decoded []byte
		decoded, err = snappy.Decode(nil, l.Data)
		if err == nil {
			err = proto.Unmarshal(decoded, &cmd)
		}
	default:
		err = fmt.Errorf("unknown raft log format: %s", s.raftLogFormat)
	}
	if err != nil {
		// This is a fatal error. We can't apply the log entry if we can't
		// decode it. This should never happen.
		log.Error("error decoding raft log entry", slog.String("error", err.Error()))
		return false, false, &v1.RaftApplyResponse{
			Time:  time.Since(start).String(),
			Error: fmt.Sprintf("unmarshal raft log entry: %s", err.Error()),
		}
	}

	var ctx context.Context
	var cancel context.CancelFunc
	if s.opts.Raft.ApplyTimeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), s.opts.Raft.ApplyTimeout)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()
	ctx = context.WithLogger(ctx, log)

	// Dispatch the log to all storage plugins when we are done.
	// This is a no-op if there are no storage plugins.
	defer func() {
		responses, err := s.plugins.ApplyRaftLog(ctx, &v1.StoreLogRequest{
			Term:  l.Term,
			Index: l.Index,
			Log:   &cmd,
		})
		if err != nil {
			log.Error("errors while dispatching logs to plugins", slog.String("error", err.Error()))
		}
		for _, res := range responses {
			log.Debug("plugin response", slog.Any("response", res))
		}
	}()

	return isEdgeChangeCmd(&cmd), isRouteChange(&cmd), raftlogs.Apply(ctx, s.weakData, &cmd)
}

func isEdgeChangeCmd(cmd *v1.RaftLogEntry) bool {
	var sql string
	if cmd.GetType() == v1.RaftCommandType_EXECUTE {
		sql = cmd.GetSqlExec().GetStatement().GetSql()
	} else {
		sql = cmd.GetSqlQuery().GetStatement().GetSql()
	}
	return sql == models.InsertNode ||
		sql == models.InsertNodeEdge ||
		sql == models.InsertNodeLease ||
		sql == models.UpdateNodeEdge ||
		sql == models.DeleteNode ||
		sql == models.DeleteNodeEdge ||
		sql == models.DeleteNodeEdges
}

func isRouteChange(cmd *v1.RaftLogEntry) bool {
	var sql string
	if cmd.GetType() == v1.RaftCommandType_EXECUTE {
		sql = cmd.GetSqlExec().GetStatement().GetSql()
	} else {
		sql = cmd.GetSqlQuery().GetStatement().GetSql()
	}
	return sql == models.PutNetworkRoute || sql == models.DeleteNetworkRoute
}
