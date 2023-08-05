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

	"github.com/webmeshproj/webmesh/pkg/meshdb"
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

func (s *Server) contextHandler(next contextDNSHandler) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		timeout := s.opts.RequestTimeout
		if timeout == 0 {
			timeout = 5 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		next(ctx, w, r)
	}
}

func (s *Server) newMsg(mesh meshdb.Store, r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = s.opts.Compression
	m.Authoritative = true
	m.RecursionAvailable = true
	if mesh != nil {
		m.Ns = []dns.RR{newNSRecord(mesh)}
	}
	return m
}

func (s *Server) writeMsg(w dns.ResponseWriter, req, reply *dns.Msg, rcode int) {
	s.log.Debug("responding to DNS question", slog.String("response", reply.String()), slog.String("rcode", dns.RcodeToString[rcode]))
	reply.SetRcode(req, rcode)
	err := w.WriteMsg(reply)
	if err != nil {
		s.log.Error("failed to write DNS response", slog.String("error", err.Error()))
	}
}

func newFQDN(mesh meshdb.Store, id string) string {
	return dns.CanonicalName(fmt.Sprintf("%s.%s", id, mesh.Domain()))
}

func newNSRecord(mesh meshdb.Store) dns.RR {
	return &dns.NS{
		Hdr: dns.RR_Header{
			Name:   dns.CanonicalName(mesh.Domain()),
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    1,
		},
		Ns: dns.CanonicalName(fmt.Sprintf("%s.%s", mesh.ID(), mesh.Domain())),
	}
}
