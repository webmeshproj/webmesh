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
	"time"

	"golang.org/x/exp/slog"

	"github.com/webmeshproj/node/pkg/meshdb/models"
	"github.com/webmeshproj/node/pkg/meshdb/networking"
)

func (s *store) onDBUpdate(op int, dbName, tableName string, rowID int64) {
	s.log.Debug("db update trigger", "op", op, "dbName", dbName, "tableName", tableName, "rowID", rowID)
	if s.testStore {
		return
	}
	switch tableName {
	case models.TableNodes, models.TableNodeEdges, models.TableLeases:
		// Potentially need to update wireguard peers
		go s.queuePeersUpdate()
	case models.TableNetworkRoutes:
		// Potentially need to update wireguard routes and peers
		go s.queuePeersUpdate()
		go s.queueRouteUpdate()
	}
}

func (s *store) queueRouteUpdate() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for s.lastAppliedIndex.Load() != s.raft.AppliedIndex() {
		if ctx.Err() != nil {
			s.log.Warn("timed out waiting for raft to catch up before applying route update")
			return
		}
		time.Sleep(time.Second)
	}
	s.nwTaskGroup.TryGo(func() error {
		nw := networking.New(s.DB())
		routes, err := nw.GetRoutesByNode(ctx, s.ID())
		if err != nil {
			s.log.Error("error getting routes by node", slog.String("error", err.Error()))
			return nil
		}
		if len(routes) > 0 {
			s.log.Debug("applied node route change, ensuring masquerade rules are in place")
			err = s.nw.StartMasquerade(ctx)
			if err != nil {
				s.log.Error("error starting masquerade", slog.String("error", err.Error()))
			}
		}
		return nil
	})
}

func (s *store) queuePeersUpdate() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for s.lastAppliedIndex.Load() != s.raft.AppliedIndex() {
		if ctx.Err() != nil {
			s.log.Warn("timed out waiting for raft to catch up before applying peer update")
			return
		}
		time.Sleep(time.Second)
	}
	s.nwTaskGroup.TryGo(func() error {
		s.log.Debug("applied batch with node edge changes, refreshing wireguard peers")
		if err := s.nw.RefreshPeers(context.Background()); err != nil {
			s.log.Error("refresh wireguard peers failed", slog.String("error", err.Error()))
		}
		return nil
	})
}
