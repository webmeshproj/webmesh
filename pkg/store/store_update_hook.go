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
	s.log.Debug("db uppdate trigger", "op", op, "dbName", dbName, "tableName", tableName, "rowID", rowID)
	if s.testStore || s.wg == nil {
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
	time.Sleep(time.Second)
	s.nwTaskGroup.TryGo(func() error {
		ctx := context.Background()
		nw := networking.New(s.DB())
		routes, err := nw.GetRoutesByNode(ctx, s.ID())
		if err != nil {
			s.log.Error("error getting routes by node", slog.String("error", err.Error()))
			return nil
		}
		if len(routes) > 0 {
			s.log.Debug("applied node route change, ensuring masquerade rules are in place")
			if !s.masquerading.Load() {
				s.wgmux.Lock()
				defer s.wgmux.Unlock()
				err = s.fw.AddMasquerade(ctx, s.wg.Name())
				if err != nil {
					s.log.Error("error adding masquerade rule", slog.String("error", err.Error()))
				} else {
					s.masquerading.Store(true)
				}
			}
		}
		return nil
	})
}

func (s *store) queuePeersUpdate() {
	time.Sleep(time.Second)
	s.nwTaskGroup.TryGo(func() error {
		s.log.Debug("applied batch with node edge changes, refreshing wireguard peers")
		if err := s.refreshWireguardPeers(context.Background()); err != nil {
			s.log.Error("refresh wireguard peers failed", slog.String("error", err.Error()))
		}
		return nil
	})
}
