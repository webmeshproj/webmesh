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
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"
	"golang.org/x/exp/slog"
	"golang.org/x/sync/errgroup"

	"github.com/webmeshproj/webmesh/pkg/meshdb"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
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
	// Forwaders are the DNS forwarders to use.
	Forwarders []string
	// CacheSize is the size of the remote DNS cache.
	CacheSize int
}

// NewServer returns a new Mesh DNS server.
func NewServer(store meshdb.Store, o *Options) *Server {
	log := slog.Default().With("component", "mesh-dns")
	srv := &Server{
		store:     store,
		peers:     peers.New(store.Storage()),
		opts:      o,
		log:       log,
		forwarder: new(dns.Client),
	}
	if srv.opts.CacheSize > 0 {
		var err error
		srv.cache, err = lru.New[string, *dns.Msg](srv.opts.CacheSize)
		if err != nil {
			log.Warn("failed to create remote lookup cache", slog.String("error", err.Error()))
		}
	}

	return srv
}

// Server is the MeshDNS server.
type Server struct {
	store     meshdb.Store
	peers     peers.Peers
	opts      *Options
	udpServer *dns.Server
	tcpServer *dns.Server
	forwarder *dns.Client
	cache     *lru.Cache[string, *dns.Msg]
	log       *slog.Logger
}

// ListenAndServe serves the Mesh DNS server.
func (s *Server) ListenAndServe() error {
	// Register the meshdns handlers
	domPattern := strings.TrimSuffix(s.store.Domain(), ".")
	timeout := s.opts.RequestTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("leader.%s", domPattern), contextHandler(timeout, s.handleLeaderLookup))
	mux.HandleFunc(fmt.Sprintf("voters.%s", domPattern), contextHandler(timeout, s.handleVotersLookup))
	mux.HandleFunc(fmt.Sprintf("observers.%s", domPattern), contextHandler(timeout, s.handleObserversLookup))
	mux.HandleFunc(domPattern, contextHandler(timeout, s.handleMeshLookup))
	mux.HandleFunc(".", contextHandler(timeout, s.handleForwardLookup))
	hdlr := s.validateRequest(s.denyZoneTransfers(mux.ServeDNS))
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
