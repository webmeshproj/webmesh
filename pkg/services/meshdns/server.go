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
	"fmt"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"
	"golang.org/x/exp/slog"
	"golang.org/x/sync/errgroup"

	"github.com/webmeshproj/webmesh/pkg/meshdb"
	dnsutil "github.com/webmeshproj/webmesh/pkg/net/system/dns"
)

// Options are the Mesh DNS server options.
type Options struct {
	// UDPListenAddr is the UDP address to listen on.
	UDPListenAddr string
	// TCPListenAddr is the TCP address to listen on.
	TCPListenAddr string
	// ReusePort enables SO_REUSEPORT on the listeners.
	// TODO: not implemented yet
	ReusePort int
	// Compression enables DNS compression.
	Compression bool
	// RequestTimeout is the timeout for DNS requests.
	// Defaults to 5 seconds.
	RequestTimeout time.Duration
	// Forwaders are the DNS forwarders to use. If empty,
	// the system DNS servers will be used.
	Forwarders []string
	// DisableForwarding disables forwarding requests to the
	// configured forwarders.
	DisableForwarding bool
	// CacheSize is the size of the remote DNS cache.
	CacheSize int
}

// NewServer returns a new Mesh DNS server.
func NewServer(o *Options) *Server {
	log := slog.Default().With("component", "mesh-dns")
	srv := &Server{
		mux:       dns.NewServeMux(),
		opts:      o,
		log:       log,
		forwarder: new(dns.Client),
		meshmuxes: make([]*meshLookupMux, 0),
	}
	if srv.opts.CacheSize > 0 {
		var err error
		srv.cache, err = lru.New[cacheKey, cacheValue](srv.opts.CacheSize)
		if err != nil {
			log.Warn("failed to create remote lookup cache", slog.String("error", err.Error()))
		}
	}
	if len(srv.opts.Forwarders) == 0 && !srv.opts.DisableForwarding {
		syscfg := dnsutil.GetSystemConfig()
		srv.opts.Forwarders = syscfg.Servers
	}
	return srv
}

// Server is the MeshDNS server.
type Server struct {
	opts      *Options
	meshmuxes []*meshLookupMux
	mux       *dns.ServeMux
	udpServer *dns.Server
	tcpServer *dns.Server
	forwarder *dns.Client
	cache     *lru.Cache[cacheKey, cacheValue]
	log       *slog.Logger
	mu        sync.Mutex
}

type cacheKey struct {
	qname string
	qtype uint16
}

type cacheValue struct {
	msg     *dns.Msg
	expires time.Time
}

// RegisterDomain registers a new domain to be served by the Mesh DNS server.
func (s *Server) RegisterDomain(mesh meshdb.Store) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Check if we have an overlapping domain. This is not a good way to run this,
	// but we'll support it for test cases.
	for _, mux := range s.meshmuxes {
		if mesh.Domain() == mux.domain {
			mux.appendMesh(mesh)
			return
		}
	}
	mux := s.newMeshLookupMux(mesh)
	s.mux.Handle(mesh.Domain(), mux)
	s.meshmuxes = append(s.meshmuxes, mux)
}

// ListenAndServe serves the Mesh DNS server.
func (s *Server) ListenAndServe() error {
	// Register the default handlers
	s.mux.HandleFunc(".", s.contextHandler(s.handleDefault))
	hdlr := s.validateRequest(s.denyZoneTransfers(s.mux.ServeDNS))
	// Start the servers
	var g errgroup.Group
	if s.opts.UDPListenAddr != "" {
		s.udpServer = &dns.Server{
			Addr:    s.opts.UDPListenAddr,
			Net:     "udp",
			Handler: hdlr,
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
			Handler: hdlr,
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
