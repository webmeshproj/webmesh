/*
Copyright 2023.

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
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/exp/slog"
	"golang.org/x/sync/errgroup"

	"gitlab.com/webmesh/node/pkg/meshdb/peers"
	"gitlab.com/webmesh/node/pkg/store"
)

// Options are the Mesh DNS server options.
type Options struct {
	// UDPListenAddr is the UDP address to listen on.
	UDPListenAddr string
	// TCPListenAddr is the TCP address to listen on.
	TCPListenAddr string
	// TSIGKey is the TSIG key to use for DNS updates.
	TSIGKey string
	// ReusePort enables SO_REUSEPORT on the listeners.
	// TODO: not implemented yet
	ReusePort int
	// Compression enables DNS compression.
	Compression bool
	// Domain is the DNS domain to serve.
	Domain string
	// RequestTimeout is the timeout for DNS requests.
	// Defaults to 5 seconds.
	RequestTimeout time.Duration
}

// NewServer returns a new Mesh DNS server.
func NewServer(store store.Store, o *Options) *Server {
	timeout := o.RequestTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if !strings.HasSuffix(o.Domain, ".") {
		o.Domain += "."
	}
	return &Server{
		store:   store,
		peers:   peers.New(store),
		opts:    o,
		soa:     fmt.Sprintf("%s.%s", store.ID(), o.Domain),
		timeout: timeout,
		log:     slog.Default().With("component", "mesh-dns"),
	}
}

type Server struct {
	store     store.Store
	peers     peers.Peers
	opts      *Options
	udpServer *dns.Server
	tcpServer *dns.Server
	soa       string
	timeout   time.Duration
	log       *slog.Logger
}

// ListenAndServe serves the Mesh DNS server.
func (s *Server) ListenAndServe() error {
	var g errgroup.Group
	if s.opts.UDPListenAddr != "" {
		s.udpServer = &dns.Server{
			Addr:    s.opts.UDPListenAddr,
			Net:     "udp",
			Handler: dns.HandlerFunc(s.handle),
		}
		if s.opts.TSIGKey != "" {
			s.log.Debug("using TSIG key for udp server")
			s.udpServer.TsigSecret = map[string]string{
				s.soa: s.opts.TSIGKey,
			}
		}
		g.Go(func() error {
			s.log.Info(fmt.Sprintf("starting meshdns udp server on %s", s.opts.UDPListenAddr))
			return s.udpServer.ListenAndServe()
		})
	}
	if s.opts.TCPListenAddr != "" {
		s.tcpServer = &dns.Server{
			Addr:    s.opts.TCPListenAddr,
			Net:     "tcp",
			Handler: dns.HandlerFunc(s.handle),
		}
		if s.opts.TSIGKey != "" {
			s.log.Debug("using TSIG key for tcp server")
			s.tcpServer.TsigSecret = map[string]string{
				s.soa: s.opts.TSIGKey,
			}
		}
		g.Go(func() error {
			s.log.Info(fmt.Sprintf("starting meshdns tcp server on %s", s.opts.UDPListenAddr))
			return s.tcpServer.ListenAndServe()
		})
	}
	return g.Wait()
}

// Shutdown shuts down the Mesh DNS server.
func (s *Server) Shutdown() error {
	var closeErr error
	if s.udpServer != nil {
		if err := s.udpServer.Shutdown(); err != nil {
			closeErr = fmt.Errorf("udp server shutdown: %w", err)
		}
	}
	if s.tcpServer != nil {
		if err := s.tcpServer.Shutdown(); err != nil {
			if closeErr != nil {
				closeErr = fmt.Errorf("tcp server shutdown: %w, %w", err, closeErr)
			} else {
				closeErr = fmt.Errorf("tcp server shutdown: %w", err)
			}
		}
	}
	return closeErr
}

func (s *Server) handle(w dns.ResponseWriter, r *dns.Msg) {
	if r == nil || len(r.Question) == 0 {
		s.log.Error("received empty DNS request")
		return
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = s.opts.Compression
	m.Authoritative = true
	m.RecursionAvailable = true

	m.Ns = []dns.RR{&dns.SOA{
		Hdr: dns.RR_Header{Name: s.opts.Domain, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 1},
		Ns:  s.soa,
	}}

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	q := r.Question[0]
	s.log.Debug("handling DNS question",
		slog.String("name", q.Name),
		slog.String("question", q.String()),
	)
	// TODO: Do an actual recursion
	nodeId := strings.Split(q.Name, ".")[0]
	peer, err := s.peers.Get(ctx, nodeId)
	if err != nil {
		s.log.Error("failed to get peer", slog.String("error", err.Error()))
		m.SetRcode(r, dns.RcodeNameError)
		err = w.WriteMsg(m)
		if err != nil {
			s.log.Error("failed to write DNS response", slog.String("error", err.Error()))
			dns.HandleFailed(w, r)
		}
		return
	}

	fqdn := fmt.Sprintf("%s.%s", nodeId, s.opts.Domain)
	switch q.Qtype {
	case dns.TypeTXT:
		s.log.Debug("handling TXT question")
		m.Answer = append(m.Answer, s.newPeerTXTRecord(fqdn, peer))
		if peer.PrivateIPv4.IsValid() {
			m.Extra = append(m.Extra, &dns.A{
				Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
				A:   peer.PrivateIPv4.Addr().AsSlice(),
			})
		}
		if peer.NetworkIPv6.IsValid() {
			m.Extra = append(m.Extra, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 1},
				AAAA: peer.NetworkIPv6.Addr().AsSlice(),
			})
		}
	case dns.TypeA:
		s.log.Debug("handling A question")
		if peer.PrivateIPv4.IsValid() {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
				A:   peer.PrivateIPv4.Addr().AsSlice(),
			})
			m.Extra = append(m.Extra, s.newPeerTXTRecord(fqdn, peer))
		} else {
			s.log.Debug("no private IPv4 address for peer")
			m.SetRcode(r, dns.RcodeNameError)
			err = w.WriteMsg(m)
			if err != nil {
				s.log.Error("failed to write DNS response", slog.String("error", err.Error()))
				dns.HandleFailed(w, r)
			}
			return
		}
	case dns.TypeAAAA:
		s.log.Debug("handling AAAA question")
		if peer.NetworkIPv6.IsValid() {
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 1},
				AAAA: peer.NetworkIPv6.Addr().AsSlice(),
			})
			m.Extra = append(m.Extra, s.newPeerTXTRecord(fqdn, peer))
		} else {
			s.log.Debug("no network IPv6 address for peer")
			m.SetRcode(r, dns.RcodeNameError)
			err = w.WriteMsg(m)
			if err != nil {
				s.log.Error("failed to write DNS response", slog.String("error", err.Error()))
				dns.HandleFailed(w, r)
			}
			return
		}
	case dns.TypeAXFR, dns.TypeIXFR:
		s.log.Debug("handling AXFR/IXFR question")
		c := make(chan *dns.Envelope)
		tr := new(dns.Transfer)
		defer close(c)
		if err := tr.Out(w, r, c); err != nil {
			return
		}
		soa, _ := dns.NewRR(fmt.Sprintf("%s 0 IN SOA %s %s %d 21600 7200 604800 3600",
			fqdn, s.soa, s.soa, time.Now().Unix()))
		c <- &dns.Envelope{RR: []dns.RR{soa}}
		w.Hijack()
		return
	}

	if r.IsTsig() != nil {
		if w.TsigStatus() == nil {
			s.log.Debug("validating TSIG")
			m.SetTsig(r.Extra[len(r.Extra)-1].(*dns.TSIG).Hdr.Name, dns.HmacMD5, 300, time.Now().Unix())
		} else {
			s.log.Error("failed to validate TSIG", slog.String("error", w.TsigStatus().Error()))
		}
	}

	s.log.Debug("responding to DNS question", slog.String("response", m.String()))
	err = w.WriteMsg(m)
	if err != nil {
		s.log.Error("failed to write DNS response", slog.String("error", err.Error()))
		dns.HandleFailed(w, r)
	}
}

func (m *Server) newPeerTXTRecord(name string, peer *peers.Node) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1},
		Txt: []string{
			fmt.Sprintf("id=%s", peer.ID),
			fmt.Sprintf("raft_port=%d", peer.RaftPort),
			fmt.Sprintf("grpc_port=%d", peer.GRPCPort),
			fmt.Sprintf("wireguard_port=%d", peer.WireguardPort),
			fmt.Sprintf("endpoint=%s", func() string {
				if peer.Endpoint.IsValid() {
					return peer.Endpoint.String()
				}
				return "<none>"
			}()),
		},
	}
}
