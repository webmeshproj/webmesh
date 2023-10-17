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

package meshnode

import (
	"context"
	"log/slog"
	"time"

	"github.com/webmeshproj/webmesh/pkg/meshnet"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

func (s *meshStore) onPeerUpdate(peers []types.MeshNode) {
	s.log.Debug("Peer update triggered")
	if s.testStore {
		return
	}
	go s.queuePeersUpdate()
	go s.queueRouteUpdate()
	if s.opts.UseMeshDNS && !s.opts.LocalDNSOnly {
		go s.queueMeshDNSUpdate()
	}
}

// TODO: Make all waits and timeouts below configurable

func (s *meshStore) queueRouteUpdate() {
	s.log.Debug("Queuing updates for routes")
	time.Sleep(time.Second * 2)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	s.routeUpdateGroup.TryGo(func() error {
		defer cancel()
		nw := s.Storage().MeshDB().Networking()
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

func (s *meshStore) queuePeersUpdate() {
	s.log.Debug("Queuing updates for peers")
	time.Sleep(time.Second * 2)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	s.peerUpdateGroup.TryGo(func() error {
		defer cancel()
		s.log.Debug("applied batch with node edge changes, refreshing wireguard peers")
		wgpeers, err := meshnet.WireGuardPeersFor(ctx, s.Storage().MeshDB(), s.ID())
		if err != nil {
			s.log.Error("error getting wireguard peers", slog.String("error", err.Error()))
			return nil
		}
		if err := s.nw.Peers().Refresh(ctx, wgpeers); err != nil {
			s.log.Error("refresh wireguard peers failed", slog.String("error", err.Error()))
		}
		return nil
	})
}

func (s *meshStore) queueMeshDNSUpdate() {
	s.log.Debug("Queuing updates for meshdns")
	time.Sleep(time.Second * 2)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	s.dnsUpdateGroup.TryGo(func() error {
		defer cancel()
		s.log.Debug("applied batch with possible DNS changes, refreshing servers")
		if err := s.nw.DNS().RefreshServers(ctx); err != nil {
			s.log.Error("refresh dnd servers failed", slog.String("error", err.Error()))
		}
		return nil
	})
}
