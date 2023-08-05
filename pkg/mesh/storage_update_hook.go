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

package mesh

import (
	"context"
	"strings"
	"time"

	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/meshdb/networking"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
)

func (s *meshStore) onDBUpdate(key, value string) {
	s.log.Debug("db update trigger", "key", key)
	if s.testStore {
		return
	}
	switch {
	case isNodeChangeKey(key):
		// Potentially need to update wireguard peers
		go s.queuePeersUpdate()
		if s.opts.Mesh != nil && s.opts.Mesh.UseMeshDNS && s.opts.Mesh.MeshDNSAdvertisePort == 0 {
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

func isNodeChangeKey(key string) bool {
	return strings.HasPrefix(key, peers.NodesPrefix) ||
		strings.HasPrefix(key, peers.EdgesPrefix)
}

func isRouteChangeKey(key string) bool {
	return strings.HasPrefix(key, networking.RoutesPrefix)
}

func (s *meshStore) queueRouteUpdate() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for s.raft.LastAppliedIndex() != s.raft.Raft().AppliedIndex() {
		if ctx.Err() != nil {
			s.log.Warn("timed out waiting for raft to catch up before applying route update")
			return
		}
		time.Sleep(time.Second)
	}
	s.routeUpdateGroup.TryGo(func() error {
		nw := networking.New(s.Storage())
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for s.raft.LastAppliedIndex() != s.raft.Raft().AppliedIndex() {
		if ctx.Err() != nil {
			s.log.Warn("timed out waiting for raft to catch up before applying peer update")
			return
		}
		time.Sleep(time.Second)
	}
	s.peerUpdateGroup.TryGo(func() error {
		s.log.Debug("applied batch with node edge changes, refreshing wireguard peers")
		if err := s.nw.RefreshPeers(context.Background()); err != nil {
			s.log.Error("refresh wireguard peers failed", slog.String("error", err.Error()))
		}
		return nil
	})
}

func (s *meshStore) queueMeshDNSUpdate() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for s.raft.LastAppliedIndex() != s.raft.Raft().AppliedIndex() {
		if ctx.Err() != nil {
			s.log.Warn("timed out waiting for raft to catch up before applying meshdns update")
			return
		}
		time.Sleep(time.Second)
	}
	s.dnsUpdateGroup.TryGo(func() error {
		s.log.Debug("applied batch with possible DNS changes, refreshing servers")
		if err := s.nw.RefreshDNSServers(context.Background()); err != nil {
			s.log.Error("refresh dnd servers failed", slog.String("error", err.Error()))
		}
		return nil
	})
}
