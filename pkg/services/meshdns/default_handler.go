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
		m := s.newMsg(nil, r)
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
		s.log.Debug("handling request with forwarding disabled")
		m := s.newMsg(nil, r)
		s.writeMsg(w, r, m, dns.RcodeNameError)
		return
	}
	s.log.Debug("handling forward lookup")
	if len(s.extforwarders) == 0 && len(s.meshforwarders) == 0 {
		// If there are no forwarders, return a NXDOMAIN
		s.log.Debug("forward request with no forwarders configured")
		m := s.newMsg(nil, r)
		s.writeMsg(w, r, m, dns.RcodeNameError)
		return
	}
	// Check the cache
	cachekey := cacheKey{q.Name, q.Qtype}
	if s.cache != nil {
		if val, ok := s.cache.Get(cachekey); ok {
			s.log.Debug("cache hit")
			if val.expires.Before(time.Now()) {
				// cached response has expired
				s.log.Debug("cached response has expired")
				s.cache.Remove(cachekey)
			} else {
				// cached response is still valid
				s.log.Debug("cached response is still valid")
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
		// Otherwise, inspect the domain to see if it's a mesh domain.
		// TODO: This is a super ugly hack assuming everyone ends in
		// .internal. Really this should be enforced by the mesh somehow.
		if strings.HasSuffix(strings.TrimSuffix(q.Name, "."), ".internal") {
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
		m, rtt, err := cli.ExchangeContext(ctx, r.Copy(), forwarder)
		if err != nil {
			if ctx.Err() != nil {
				s.log.Error("failed to forward lookup", slog.String("error", err.Error()))
				m := s.newMsg(nil, r)
				s.writeMsg(w, r, m, dns.RcodeServerFailure)
				return
			}
			// Try the next forwarder
			s.log.Debug("forward lookup failed", slog.String("error", err.Error()))
			continue
		}
		s.log.Debug("forward lookup succeeded", slog.Duration("rtt", rtt))
		if m.Rcode != dns.RcodeNameError {
			// If the forwarder returned a non-NXDOMAIN response, save it in the cache
			// and return it
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
	}
	// If all forwarders returned NXDOMAIN, return NXDOMAIN
	m := s.newMsg(nil, r)
	s.writeMsg(w, r, m, dns.RcodeNameError)
}
