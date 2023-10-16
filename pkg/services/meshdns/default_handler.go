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
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/webmeshproj/webmesh/pkg/context"
)

func (s *Server) handleDefault(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	q := r.Question[0]
	if q.Qtype == dns.TypeNS && q.Name == "." {
		// This is a root NS request, return the configured root NS records
		s.log.Debug("handling root NS request")
		m := s.newMsg(meshDomain{}, r)
		for _, mux := range s.meshmuxes {
			mux.mu.RLock()
			m.Ns = append(m.Ns, newNSRecord(mux.meshes[0]))
			m.Answer = append(m.Answer, newNSRecord(mux.meshes[0]))
			mux.mu.RUnlock()
		}
		s.writeMsg(w, r, m, dns.RcodeSuccess)
		return
	}
	if s.opts.DisableForwarding {
		// We're not forwarding, so return NXDOMAIN
		s.log.Debug("Handling request with forwarding disabled")
		m := s.newMsg(meshDomain{}, r)
		s.writeMsg(w, r, m, dns.RcodeNameError)
		return
	}
	s.log.Debug("Handling forward lookup")
	if len(s.extforwarders) == 0 && len(s.meshforwarders) == 0 {
		// If there are no forwarders, return a NXDOMAIN
		s.log.Debug("Forward request with no forwarders configured")
		m := s.newMsg(meshDomain{}, r)
		s.writeMsg(w, r, m, dns.RcodeNameError)
		return
	}
	// Check the cache
	cachekey := cacheKey{q.Name, q.Qtype}
	if s.cache != nil {
		if val, ok := s.cache.Get(cachekey); ok {
			s.log.Debug("DNS Cache hit")
			if val.expires.Before(time.Now()) {
				// cached response has expired
				s.log.Debug("Cached response has expired")
				s.cache.Remove(cachekey)
			} else {
				// cached response is still valid
				s.log.Debug("Cached response is still valid")
				m := val.msg.Copy()
				s.writeMsg(w, r, m, m.Rcode)
				return
			}
		}
	}
	// determine our forwarding order
	var forwarders []string
	if q.Qclass == dns.ClassCHAOS {
		// If this is a CHAOS query, only use the mesh forwarders
		forwarders = s.meshforwarders
	} else {
		var isMeshDomain bool
		for _, mux := range s.meshmuxes {
			if strings.HasSuffix(strings.TrimSuffix(q.Name, "."), strings.TrimSuffix(mux.domain, ".")) {
				// We technically know the exact forwarder to try first.
				// But we also support duplicate domains, so we'll just
				// prioritize mesh forwarders.
				isMeshDomain = true
				break
			}
		}
		if isMeshDomain {
			// Prioritize mesh forwarders
			forwarders = append(s.meshforwarders, s.extforwarders...)
		} else {
			// Prioritize external forwarders
			forwarders = append(s.extforwarders, s.meshforwarders...)
		}
	}
	cli := new(dns.Client)
	cli.Timeout = time.Second // TODO: Make this configurable
	for _, forwarder := range forwarders {
		s.log.Debug("Forwarding lookup", slog.String("forwarder", forwarder))
		m, rtt, err := cli.ExchangeContext(ctx, r.Copy(), forwarder)
		if err != nil {
			if ctx.Err() != nil {
				s.log.Error("Failed to forward lookup", slog.String("error", err.Error()))
				m := s.newMsg(meshDomain{}, r)
				s.writeMsg(w, r, m, dns.RcodeServerFailure)
				return
			}
			// Try the next forwarder
			s.log.Debug("Forward lookup failed", slog.String("error", err.Error()))
			continue
		}
		s.log.Debug("Forward lookup succeeded", slog.Duration("rtt", rtt))
		if m.Rcode != dns.RcodeNameError {
			// If the forwarder returned a non-NXDOMAIN response, save it in the cache
			// and return it
			s.log.Debug("Received non-NXDOMAIN response from forwarder, returning", slog.Int("rcode", m.Rcode))
			if s.cache != nil {
				cacheValue := cacheValue{
					msg: m.Copy(),
					// Use the first TTL in the answer section as the cache TTL
					expires: func() time.Time {
						if len(m.Answer) > 0 {
							ttl := time.Duration(m.Answer[0].Header().Ttl) * time.Second
							if ttl > 0 {
								return time.Now().Add(ttl)
							}
						}
						// Default to 5 minutes
						return time.Now().Add(5 * time.Minute)
					}(),
				}
				s.cache.Add(cachekey, cacheValue)
			}
			s.writeMsg(w, r, m, m.Rcode)
			return
		}
		// If the forwarder returned NXDOMAIN, try the next forwarder
		s.log.Debug("Received NXDOMAIN response from forwarder, trying next forwarder")
	}
	// If all forwarders returned NXDOMAIN, return NXDOMAIN with our first
	// registered mesh as the SOA.
	m := s.newMsg(s.meshmuxes[0].meshes[0], r)
	s.writeMsg(w, r, m, dns.RcodeNameError)
}
