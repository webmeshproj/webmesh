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
	"bytes"
	"context"
	"log/slog"
	"time"

	"github.com/webmeshproj/webmesh/pkg/storage/meshdb/graph"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb/networking"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb/peers"
)

func (s *meshStore) onDBUpdate(key, value []byte) {
	s.log.Debug("Store update triggered", "key", string(key))
	if s.testStore {
		return
	}
	switch {
	case isNodeChangeKey(key):
		// Potentially need to update wireguard peers
		go s.queuePeersUpdate()
		if s.opts.UseMeshDNS {
			// Peer update, we want to use meshdns, and we dont have our own server
			// so we need to refresh the meshdns servers
			go s.queueMeshDNSUpdate()
		}
	case isRouteChangeKey(key):
		// Potentially need to update wireguard routes and peers
		go s.queuePeersUpdate()
		go s.queueRouteUpdate()
	}
}

func isNodeChangeKey(key []byte) bool {
	return bytes.HasPrefix(key, graph.NodesPrefix) || bytes.HasPrefix(key, graph.EdgesPrefix)
}

func isRouteChangeKey(key []byte) bool {
	return bytes.HasPrefix(key, networking.RoutesPrefix)
}

// TODO: Make all waits and timeouts below configurable

func (s *meshStore) queueRouteUpdate() {
	time.Sleep(time.Second * 2)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	s.routeUpdateGroup.TryGo(func() error {
		defer cancel()
		nw := networking.New(s.Storage().MeshStorage())
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
	time.Sleep(time.Second * 2)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	s.peerUpdateGroup.TryGo(func() error {
		defer cancel()
		s.log.Debug("applied batch with node edge changes, refreshing wireguard peers")
		wgpeers, err := peers.WireGuardPeersFor(ctx, s.Storage().MeshStorage(), s.ID())
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
