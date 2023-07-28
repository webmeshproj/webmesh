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
	"github.com/miekg/dns"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/context"
)

func (s *Server) handleDefault(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	q := r.Question[0]
	if q.Qtype == dns.TypeNS && q.Name == "." {
		// This is a root NS request, return the configured root NS records
		s.log.Debug("handling root NS request")
		// newMsg automatically adds the NS records for the root zone
		m := s.newMsg(r)
		s.writeMsg(w, r, m, dns.RcodeSuccess)
		return
	}
	s.log.Debug("handling forward lookup")
	if len(s.opts.Forwarders) == 0 {
		// If there are no forwarders, return a NXDOMAIN
		s.log.Debug("forward request with no forwarders configured")
		m := s.newMsg(r)
		s.writeMsg(w, r, m, dns.RcodeNameError)
		return
	}
	for _, forwarder := range s.opts.Forwarders {
		m, rtt, err := s.forwarder.ExchangeContext(ctx, r, forwarder)
		if err != nil {
			s.log.Error("failed to forward lookup", slog.String("error", err.Error()))
			s.writeMsg(w, r, m, dns.RcodeServerFailure)
			return
		}
		s.log.Debug("forward lookup succeeded", slog.Duration("rtt", rtt))
		if m.Rcode != dns.RcodeNameError {
			s.writeMsg(w, r, m, m.Rcode)
			return
		}
		// If the forwarder returned NXDOMAIN, try the next forwarder
	}
	// If all forwarders returned NXDOMAIN, return NXDOMAIN
	m := s.newMsg(r)
	s.writeMsg(w, r, m, dns.RcodeNameError)
}
