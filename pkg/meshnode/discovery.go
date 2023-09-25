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
	st          *meshStore
	discoveries map[string]io.Closer
	mu          sync.Mutex
}

func newMeshStoreAnnouncer(st *meshStore) *meshStoreAnnouncer {
	return &meshStoreAnnouncer{
		st:          st,
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
	s.mu.Lock()
	defer s.mu.Unlock()
	log := context.LoggerFrom(ctx)
	log.Info("Announcing peer discovery service")
	var discover io.Closer
	var err error
	discover, err = libp2p.NewJoinAnnouncer(ctx, opts, transport.JoinServerFunc(s.proxyJoin))
	if err != nil {
		return fmt.Errorf("new join announcer: %w", err)
	}
	s.discoveries[opts.Rendezvous] = discover
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
	log.Info("Proxying join to cluster")
	c, err := s.st.DialLeader(ctx)
	if err != nil {
		log.Error("Failed to dial leader", slog.String("error", err.Error()))
		return nil, err
	}
	defer c.Close()
	ctx = metadata.AppendToOutgoingContext(ctx, leaderproxy.ProxiedFromMeta, s.st.ID())
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
