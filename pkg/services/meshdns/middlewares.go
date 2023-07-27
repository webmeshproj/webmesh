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

// Package meshdns contains the Mesh DNS server.
package meshdns

import (
	"context"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
)

type contextDNSHandler func(context.Context, dns.ResponseWriter, *dns.Msg)

func contextHandler(timeout time.Duration, next contextDNSHandler) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		next(ctx, w, r)
	}
}

func errToRcode(err error) int {
	switch err {
	case nil:
		return dns.RcodeSuccess
	case context.DeadlineExceeded:
		return dns.RcodeServerFailure
	case peers.ErrNodeNotFound, errNoIPv4, errNoIPv6:
		return dns.RcodeNameError
	default:
		return dns.RcodeServerFailure
	}
}

func (s *Server) newMsg(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = s.opts.Compression
	m.Authoritative = true
	m.RecursionAvailable = true
	// m.Response = true
	m.Ns = []dns.RR{&dns.SOA{
		Hdr: dns.RR_Header{Name: s.store.Domain(), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 1},
		Ns:  s.soa,
	}}
	return m
}

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

func (s *Server) writeMsg(w dns.ResponseWriter, req, reply *dns.Msg, rcode int) {
	s.log.Debug("responding to DNS question",
		slog.String("response", reply.String()),
		slog.String("rcode", dns.RcodeToString[rcode]))
	reply.SetRcode(req, rcode)
	err := w.WriteMsg(reply)
	if err != nil {
		s.log.Error("failed to write DNS response", slog.String("error", err.Error()))
	}
}
