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
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

type meshLookupMux struct {
	*dns.ServeMux
	*Server
	domain   string
	ipv6Only bool
	meshes   []meshDomain
	cancels  []context.CancelFunc
	mu       sync.RWMutex
}

func (m *meshLookupMux) cancel() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, cancel := range m.cancels {
		cancel()
	}
	m.cancels = nil
}

type meshDomain struct {
	nodeID   types.NodeID
	domain   string
	storage  storage.Provider
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
	s.log.Debug("Handling mesh lookup")
	for _, mesh := range s.meshes {
		m := s.newMsg(mesh, r)
		name := strings.TrimSuffix(r.Question[0].Name, ".")
		trimDomain := strings.TrimSuffix(mesh.domain, ".")
		trimName := strings.TrimSuffix(name, trimDomain)
		parts := strings.Split(trimName, ".")
		if len(parts) > 1 {
			s.log.Debug("Request is not for the root domain", slog.String("domain", mesh.domain), slog.String("name", name))
			// This is for this domain, but not the root
			// We pass it to the next or default handler
			continue
		}
		if len(parts) == 0 {
			// This is the root, so we return the configured root NS records
			s.log.Debug("Handling root NS request for domain", slog.String("domain", mesh.domain))
			for _, mux := range s.meshmuxes {
				mux.mu.RLock()
				m.Ns = append(m.Ns, newNSRecord(mesh))
				m.Answer = append(m.Answer, newNSRecord(mesh))
				mux.mu.RUnlock()
			}
			s.writeMsg(w, r, m, dns.RcodeSuccess)
			return
		}
		nodeID := parts[0]
		err := s.appendPeerToMessage(ctx, mesh, r, m, nodeID, s.ipv6Only)
		if err != nil {
			if errors.IsNodeNotFound(err) {
				// Try the next mesh
				continue
			}
			s.writeMsg(w, r, m, errToRcode(err))
			return
		}
		s.writeMsg(w, r, m, dns.RcodeSuccess)
		return
	}
	// Fall down to the default handler
	s.log.Debug("Falling down to default handler")
	s.handleDefault(ctx, w, r)
}

func (s *meshLookupMux) handleLeaderLookup(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.log.Debug("Handling leader lookup")
	// We only serve these for the first registered mesh
	// TODO: Determine where the request came from
	mesh := s.meshes[0]
	m := s.newMsg(mesh, r)
	leader, err := mesh.storage.Consensus().GetLeader(ctx)
	if err != nil {
		s.log.Error("Failed to get leader", slog.String("error", err.Error()))
		s.writeMsg(w, r, m, dns.RcodeServerFailure)
		return
	}
	nodeID := string(leader.GetId())
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
	s.log.Debug("Handling voters lookup")
	// We only serve these for the first registered mesh
	// TODO: Determine where the request came from
	mesh := s.meshes[0]
	m := s.newMsg(mesh, r)
	status := mesh.storage.Status()
	for _, server := range status.GetPeers() {
		if status.ClusterStatus == v1.ClusterStatus_CLUSTER_VOTER {
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: newFQDN(mesh, "voters"), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1},
				Target: newFQDN(mesh, server.GetId()),
			})
			err := s.appendPeerToMessage(ctx, mesh, r, m, server.GetId(), s.ipv6Only)
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
	s.log.Debug("Handling observers lookup")
	// We only serve these for the first registered mesh
	// TODO: Determine where the request came from
	mesh := s.meshes[0]
	m := s.newMsg(mesh, r)
	status := mesh.storage.Status()
	for _, server := range status.GetPeers() {
		if server.ClusterStatus == v1.ClusterStatus_CLUSTER_OBSERVER {
			m.Answer = append(m.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: newFQDN(mesh, "observers"), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1},
				Target: newFQDN(mesh, server.GetId()),
			})
			err := s.appendPeerToMessage(ctx, mesh, r, m, server.GetId(), s.ipv6Only)
			if err != nil {
				s.writeMsg(w, r, m, errToRcode(err))
				return
			}
		}
	}
	s.writeMsg(w, r, m, dns.RcodeSuccess)
}
