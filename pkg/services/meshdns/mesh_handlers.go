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
	"strings"

	"github.com/hashicorp/raft"
	"github.com/miekg/dns"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb"
)

func (s *Server) meshLookupHandler(mesh meshdb.Store) contextDNSHandler {
	return func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		s.log.Debug("handling leader lookup")
		m := s.newMsg(mesh, r)
		nodeID := strings.Split(r.Question[0].Name, ".")[0]
		err := s.appendPeerToMessage(ctx, mesh, r, m, nodeID)
		if err != nil {
			s.writeMsg(w, r, m, errToRcode(err))
			return
		}
		s.writeMsg(w, r, m, dns.RcodeSuccess)
	}
}

func (s *Server) leaderLookupHandler(mesh meshdb.Store) contextDNSHandler {
	return func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		s.log.Debug("handling leader lookup")
		m := s.newMsg(mesh, r)
		leaderID, err := mesh.Leader()
		if err != nil {
			s.log.Error("failed to get leader", slog.String("error", err.Error()))
			s.writeMsg(w, r, m, dns.RcodeServerFailure)
			return
		}
		nodeID := string(leaderID)
		// Add a CNAME record for the leader
		m.Answer = append(m.Answer, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: newFQDN(mesh, "leader"), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1},
			Target: newFQDN(mesh, nodeID),
		})
		err = s.appendPeerToMessage(ctx, mesh, r, m, nodeID)
		if err != nil {
			s.writeMsg(w, r, m, errToRcode(err))
			return
		}
		s.writeMsg(w, r, m, dns.RcodeSuccess)
	}
}

func (s *Server) votersLookupHandler(mesh meshdb.Store) contextDNSHandler {
	return func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		s.log.Debug("handling voters lookup")
		m := s.newMsg(mesh, r)
		config := mesh.Raft().Configuration()
		for _, server := range config.Servers {
			if server.Suffrage == raft.Voter {
				m.Answer = append(m.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: newFQDN(mesh, "voters"), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1},
					Target: newFQDN(mesh, string(server.ID)),
				})
				err := s.appendPeerToMessage(ctx, mesh, r, m, string(server.ID))
				if err != nil {
					s.writeMsg(w, r, m, errToRcode(err))
					return
				}
			}
		}
		s.writeMsg(w, r, m, dns.RcodeSuccess)
	}
}

func (s *Server) observersLookupHandler(mesh meshdb.Store) contextDNSHandler {
	return func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		s.log.Debug("handling observers lookup")
		m := s.newMsg(mesh, r)
		config := mesh.Raft().Configuration()
		for _, server := range config.Servers {
			if server.Suffrage == raft.Nonvoter {
				m.Answer = append(m.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: newFQDN(mesh, "voters"), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1},
					Target: newFQDN(mesh, string(server.ID)),
				})
				err := s.appendPeerToMessage(ctx, mesh, r, m, string(server.ID))
				if err != nil {
					s.writeMsg(w, r, m, errToRcode(err))
					return
				}
			}
		}
		s.writeMsg(w, r, m, dns.RcodeSuccess)
	}
}
