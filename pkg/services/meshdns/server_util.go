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
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
)

type errNoIPv4 struct{}

func (e errNoIPv4) Error() string {
	return "no IPv4 address"
}

type errNoIPv6 struct{}

func (e errNoIPv6) Error() string {
	return "no IPv6 address"
}

func errToRcode(err error) int {
	switch err {
	case nil:
		return dns.RcodeSuccess
	case context.DeadlineExceeded:
		return dns.RcodeServerFailure
	case peers.ErrNodeNotFound, errNoIPv4{}, errNoIPv6{}:
		return dns.RcodeNameError
	default:
		return dns.RcodeServerFailure
	}
}

type contextDNSHandler func(context.Context, dns.ResponseWriter, *dns.Msg)

func contextHandler(timeout time.Duration, next contextDNSHandler) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		next(ctx, w, r)
	}
}

func (s *Server) newFQDN(id string) string {
	return fmt.Sprintf("%s.%s", id, s.store.Domain())
}

func (s *Server) newNSRecord() dns.RR {
	return &dns.NS{
		Hdr: dns.RR_Header{
			Name:     s.store.Domain(),
			Rrtype:   dns.TypeNS,
			Class:    dns.ClassINET,
			Ttl:      1,
			Rdlength: 0,
		},
		Ns: fmt.Sprintf("%s.%s", s.store.ID(), s.store.Domain()),
	}
}

func (s *Server) newMsg(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = s.opts.Compression
	m.Authoritative = true
	m.RecursionAvailable = true
	// m.Response = true
	m.Ns = []dns.RR{s.newNSRecord()}
	return m
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
