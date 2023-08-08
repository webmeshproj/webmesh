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

	"github.com/miekg/dns"
)

func (s *Server) validateRequest(next dns.HandlerFunc) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		if r == nil || len(r.Question) == 0 {
			s.log.Warn("received empty DNS request")
			m := new(dns.Msg)
			m.SetReply(r)
			s.writeMsg(w, r, m, dns.RcodeFormatError)
			return
		}
		q := r.Question[0]
		s.log.Debug("handling DNS question", slog.String("name", q.Name), slog.String("question", q.String()))
		next(w, r)
	}
}

func (s *Server) denyZoneTransfers(next dns.HandlerFunc) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		for _, q := range r.Question {
			if q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR {
				s.log.Warn("denying zone transfer request")
				m := new(dns.Msg)
				m.SetReply(r)
				s.writeMsg(w, r, m, dns.RcodeRefused)
				return
			}
		}
		next(w, r)
	}
}
