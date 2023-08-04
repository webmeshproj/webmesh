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
	"time"

	"github.com/miekg/dns"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/context"
)

func (s *Server) handleDefault(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	q := r.Question[0]
	if q.Qtype == dns.TypeNS && q.Name == "." {
		// This is a root NS request, return the configured root NS records
		s.log.Debug("handling root NS request")
		m := s.newMsg(nil, r)
		for _, st := range s.stores {
			m.Ns = append(m.Ns, newNSRecord(st))
			m.Answer = append(m.Answer, newNSRecord(st))
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
	if len(s.opts.Forwarders) == 0 {
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
	for _, forwarder := range s.opts.Forwarders {
		m, rtt, err := s.forwarder.ExchangeContext(ctx, r, forwarder)
		if err != nil {
			s.log.Error("failed to forward lookup", slog.String("error", err.Error()))
			m := s.newMsg(nil, r)
			s.writeMsg(w, r, m, dns.RcodeServerFailure)
			return
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
