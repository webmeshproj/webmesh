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

package meshdns

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	"github.com/webmeshproj/webmesh/pkg/raft"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

type meshLookupMux struct {
	*dns.ServeMux
	*Server
	domain   string
	ipv6Only bool
	meshes   []meshDomain
	mu       sync.RWMutex
}

type meshDomain struct {
	domain   string
	storage  storage.MeshStorage
	raft     raft.Raft
	ipv6Only bool
}

func (s *Server) newMeshLookupMux(dom meshDomain) *meshLookupMux {
	mux := &meshLookupMux{
		ServeMux: dns.NewServeMux(),
		Server:   s,
		domain:   dom.domain,
		meshes:   []meshDomain{dom},
		ipv6Only: dom.ipv6Only,
	}
	domPattern := strings.TrimSuffix(dom.domain, ".")
	mux.HandleFunc(fmt.Sprintf("leader.%s", domPattern), s.contextHandler(mux.handleLeaderLookup))
	mux.HandleFunc(fmt.Sprintf("voters.%s", domPattern), s.contextHandler(mux.handleVotersLookup))
	mux.HandleFunc(fmt.Sprintf("observers.%s", domPattern), s.contextHandler(mux.handleObserversLookup))
	mux.HandleFunc(domPattern, s.contextHandler(mux.handleMeshLookup))
	return mux
}

func (s *meshLookupMux) appendMesh(dom meshDomain) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.meshes = append(s.meshes, dom)
}

func (s *meshLookupMux) handleMeshLookup(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.log.Debug("handling mesh lookup")
	for _, mesh := range s.meshes {
		m := s.newMsg(mesh, r)
		nodeID := strings.Split(r.Question[0].Name, ".")[0]
		err := s.appendPeerToMessage(ctx, mesh, r, m, nodeID, s.ipv6Only)
		if err != nil {
			if err == peers.ErrNodeNotFound {
				// Try the next mesh
				continue
			}
			s.writeMsg(w, r, m, errToRcode(err))
			return
		}
		s.writeMsg(w, r, m, dns.RcodeSuccess)
	}
	// NXDOMAIN
	m := s.newMsg(s.meshes[0], r) // TODO: Match the NS record to our ID where the request came from
	s.writeMsg(w, r, m, dns.RcodeNameError)
}

func (s *meshLookupMux) handleLeaderLookup(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.log.Debug("handling leader lookup")
	// We only serve these for the first registered mesh
	// TODO: Determine where the request came from
	mesh := s.meshes[0]
	m := s.newMsg(mesh, r)
	leaderID, err := mesh.raft.LeaderID()
	if err != nil {
		s.log.Error("failed to get leader", slog.String("error", err.Error()))
		s.writeMsg(w, r, m, dns.RcodeServerFailure)
		return
	}
	nodeID := string(leaderID)
	m.Answer = append(m.Answer, &dns.CNAME{
		Hdr:    dns.RR_Header{Name: newFQDN(mesh, "leader"), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1},
		Target: newFQDN(mesh, nodeID),
	})
	err = s.appendPeerToMessage(ctx, mesh, r, m, nodeID, s.ipv6Only)
	if err != nil {
		s.writeMsg(w, r, m, errToRcode(err))
		return
	}
	s.writeMsg(w, r, m, dns.RcodeSuccess)
}

func (s *meshLookupMux) handleVotersLookup(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.log.Debug("handling voters lookup")
	// We only serve these for the first registered mesh
	// TODO: Determine where the request came from
	mesh := s.meshes[0]
	m := s.newMsg(mesh, r)
	config, err := mesh.raft.Configuration()
	if err != nil {
		s.log.Error("failed to get configuration", slog.String("error", err.Error()))
		s.writeMsg(w, r, m, dns.RcodeServerFailure)
		return
	}
	for _, server := range config.Servers {
		if server.Suffrage == raft.Voter {
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: newFQDN(mesh, "voters"), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1},
				Target: newFQDN(mesh, string(server.ID)),
			})
			err := s.appendPeerToMessage(ctx, mesh, r, m, string(server.ID), s.ipv6Only)
			if err != nil {
				s.writeMsg(w, r, m, errToRcode(err))
				return
			}
		}
	}
	s.writeMsg(w, r, m, dns.RcodeSuccess)
}

func (s *meshLookupMux) handleObserversLookup(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.log.Debug("handling observers lookup")
	// We only serve these for the first registered mesh
	// TODO: Determine where the request came from
	mesh := s.meshes[0]
	m := s.newMsg(mesh, r)
	config, err := mesh.raft.Configuration()
	if err != nil {
		s.log.Error("failed to get configuration", slog.String("error", err.Error()))
		s.writeMsg(w, r, m, dns.RcodeServerFailure)
		return
	}
	for _, server := range config.Servers {
		if server.Suffrage == raft.Nonvoter {
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: newFQDN(mesh, "voters"), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1},
				Target: newFQDN(mesh, string(server.ID)),
			})
			err := s.appendPeerToMessage(ctx, mesh, r, m, string(server.ID), s.ipv6Only)
			if err != nil {
				s.writeMsg(w, r, m, errToRcode(err))
				return
			}
		}
	}
	s.writeMsg(w, r, m, dns.RcodeSuccess)
}
