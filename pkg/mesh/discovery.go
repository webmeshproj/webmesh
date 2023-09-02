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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/metadata"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/net/transport/libp2p"
	"github.com/webmeshproj/webmesh/pkg/services/leaderproxy"
)

type meshStoreAnnouncer struct {
	nodeID      string
	dialer      transport.LeaderDialer
	discoveries map[string]io.Closer
	mu          sync.Mutex
}

func newMeshStoreAnnouncer(nodeID string, dialer transport.LeaderDialer) *meshStoreAnnouncer {
	return &meshStoreAnnouncer{
		nodeID:      nodeID,
		dialer:      dialer,
		discoveries: make(map[string]io.Closer),
	}
}

func (s *meshStoreAnnouncer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	for _, d := range s.discoveries {
		if err := d.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("error closing discoveries: %w", errors.Join(errs...))
	}
	return nil
}

func (s *meshStoreAnnouncer) AnnounceToDHT(ctx context.Context, opts libp2p.AnnounceOptions) error {
	log := context.LoggerFrom(ctx)
	log.Info("Announcing peer discovery service")
	discover, err := libp2p.NewJoinAnnouncer(ctx, opts, transport.JoinServerFunc(s.proxyJoin))
	if err != nil {
		return fmt.Errorf("new kad dht announcer: %w", err)
	}
	s.mu.Lock()
	s.discoveries[opts.Rendezvous] = discover
	s.mu.Unlock()
	return nil
}

func (s *meshStoreAnnouncer) LeaveDHT(ctx context.Context, psk string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.discoveries[psk]; ok {
		if err := d.Close(); err != nil {
			return err
		}
		delete(s.discoveries, psk)
	}
	return nil
}

func (s *meshStoreAnnouncer) proxyJoin(ctx context.Context, req *v1.JoinRequest) (*v1.JoinResponse, error) {
	// We don't need to go through the extra overhead of dialing
	// ourself if we are the current leader. This is a TODO.
	log := context.LoggerFrom(ctx)
	c, err := s.dialer.DialLeader(ctx)
	if err != nil {
		log.Error("Failed to dial leader", slog.String("error", err.Error()))
		return nil, err
	}
	defer c.Close()
	ctx = metadata.AppendToOutgoingContext(ctx, leaderproxy.ProxiedFromMeta, s.nodeID)
	// We are not autneticating the request beyond whatever pre-shared key was used to get
	// here. So for now we'll assume the ID is valid. This is a TODO.
	ctx = metadata.AppendToOutgoingContext(ctx, leaderproxy.ProxiedForMeta, req.GetId())
	resp, err := v1.NewMembershipClient(c).Join(ctx, req)
	if err != nil {
		log.Error("Failed to proxy join to cluster", slog.String("error", err.Error()))
		return nil, err
	}
	return resp, nil
}
