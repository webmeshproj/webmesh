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
	"log/slog"
	"net"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/sync/errgroup"

	"github.com/webmeshproj/webmesh/pkg/context"
	dnsutil "github.com/webmeshproj/webmesh/pkg/meshnet/system/dns"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// DefaultAdvertisePort is the default port to advertise for Mesh DNS.
const DefaultAdvertisePort = 53

// DefaultListenUDP is the default UDP listen address.
const DefaultListenUDP = "[::]:53"

// DefaultListenTCP is the default TCP listen address.
const DefaultListenTCP = "[::]:53"

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
	// IncludeSystemResolvers includes the system DNS
	// servers in the forwarders list if it is non-empty.
	IncludeSystemResolvers bool
	// DisableForwarding disables forwarding requests to the
	// configured forwarders.
	DisableForwarding bool
	// CacheSize is the size of the remote DNS cache.
	CacheSize int
}

// NewServer returns a new Mesh DNS server.
func NewServer(ctx context.Context, o *Options) *Server {
	log := context.LoggerFrom(ctx).With("component", "mesh-dns")
	srv := &Server{
		mux:            dns.NewServeMux(),
		opts:           o,
		log:            log,
		extforwarders:  make([]string, 0),
		meshforwarders: make([]string, 0),
		meshmuxes:      make([]*meshLookupMux, 0),
	}
	if srv.opts.CacheSize > 0 {
		var err error
		srv.cache, err = lru.New[cacheKey, cacheValue](srv.opts.CacheSize)
		if err != nil {
			log.Warn("failed to create remote lookup cache", slog.String("error", err.Error()))
		}
	}
	forwarders := o.Forwarders
	if len(forwarders) == 0 && o.IncludeSystemResolvers && !o.DisableForwarding {
		syscfg := dnsutil.GetSystemConfig()
		forwarders = append(forwarders, syscfg.Servers...)
	}
	srv.extforwarders = append(srv.extforwarders, forwarders...)
	return srv
}

// Server is the MeshDNS server.
type Server struct {
	opts           *Options
	meshmuxes      []*meshLookupMux
	mux            *dns.ServeMux
	udpServer      *dns.Server
	tcpServer      *dns.Server
	extforwarders  []string
	meshforwarders []string
	cache          *lru.Cache[cacheKey, cacheValue]
	log            *slog.Logger
	mu             sync.RWMutex
}

// UpsertForwarder upserts a forwarder into the static forwarders list.
func (s *Server) UpsertForwarder(forwarder string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, fwd := range s.extforwarders {
		if fwd == forwarder {
			return
		}
	}
	s.extforwarders = append(s.extforwarders, forwarder)
}

// PushForwarder pushes a forwarder to the front of the static forwarders list.
func (s *Server) PushForwarder(forwarder string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, fwd := range s.extforwarders {
		if fwd == forwarder {
			if i == 0 {
				return
			}
			s.extforwarders = append(s.extforwarders[:i], s.extforwarders[i+1:]...)
			s.extforwarders = append([]string{forwarder}, s.extforwarders...)
			return
		}
	}
	s.extforwarders = append([]string{forwarder}, s.extforwarders...)
}

// RemoveForwarder removes a forwarder from the static forwarders list.
func (s *Server) RemoveForwarder(forwarder string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, fwd := range s.extforwarders {
		if fwd == forwarder {
			s.extforwarders = append(s.extforwarders[:i], s.extforwarders[i+1:]...)
			return
		}
	}
}

// ReplaceForwarders replaces the static forwarders list with the given list.
func (s *Server) ReplaceForwarders(forwarders []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.extforwarders = forwarders
}

type cacheKey struct {
	qname string
	qtype uint16
}

type cacheValue struct {
	msg     *dns.Msg
	expires time.Time
}

type DomainOptions struct {
	// NodeID is the node ID to use for this domain.
	NodeID types.NodeID
	// MeshDomain is the domain to serve.
	MeshDomain string
	// MeshStorage is the storage for the mesh that this domain belongs to.
	MeshStorage storage.Provider
	// IPv6Only indicates that this domain should only respond to IPv6 requests.
	IPv6Only bool
	// SubscribeForwarders indicates that new forwarders added to the mesh should be
	// appeneded to the current server.
	SubscribeForwarders bool
}

// ListenPortUDP returns the UDP listen port.
func (s *Server) ListenPortUDP() int {
	if s.udpServer == nil {
		return 0
	}
	return s.udpServer.PacketConn.LocalAddr().(*net.UDPAddr).Port
}

// ListenPortTCP returns the TCP listen port.
func (s *Server) ListenPortTCP() int {
	if s.tcpServer == nil {
		return 0
	}
	return s.tcpServer.Listener.Addr().(*net.TCPAddr).Port
}

// ListenPort returns the UDP or TDP listen port in that order
// depending on which is available.
func (s *Server) ListenPort() int {
	if s.ListenPortUDP() > 0 {
		return s.ListenPortUDP()
	}
	return s.ListenPortTCP()
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
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var closeErr error
	for _, mux := range s.meshmuxes {
		mux.cancel()
	}
	s.log.Info("Shutting down meshdns server")
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

// DeregisterDomain deregisters a domain from the Mesh DNS server.
func (s *Server) DeregisterDomain(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, mux := range s.meshmuxes {
		if mux.domain == domain {
			s.meshmuxes = append(s.meshmuxes[:i], s.meshmuxes[i+1:]...)
			mux.cancel()
			return
		}
	}
}

// RegisterDomain registers a new domain to be served by the Mesh DNS server.
func (s *Server) RegisterDomain(opts DomainOptions) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dom := meshDomain{
		nodeID:   opts.NodeID,
		domain:   opts.MeshDomain,
		storage:  opts.MeshStorage,
		ipv6Only: opts.IPv6Only,
	}
	// Check if we have an overlapping domain. This is not a good way to run this,
	// but we'll support it for test cases. A flag should maybe be exposed to cause
	// this to error.
	var mux *meshLookupMux
	for _, mu := range s.meshmuxes {
		if opts.MeshDomain == mu.domain {
			mu.appendMesh(dom)
			mux = mu
			break
		}
	}
	if mux == nil {
		mux = s.newMeshLookupMux(dom)
		s.mux.Handle(dom.domain, mux)
		s.meshmuxes = append(s.meshmuxes, mux)
	}
	if opts.SubscribeForwarders {
		updateForwarders := func(peers []types.MeshNode) {
			// Gather forwarders
			seen := make(map[string]bool)
			for _, peer := range peers {
				if peer.PrivateDNSAddrV4().IsValid() && !opts.IPv6Only {
					// Prefer IPv4
					seen[peer.PrivateDNSAddrV4().String()] = true
					continue
				} else if peer.PrivateDNSAddrV6().IsValid() {
					seen[peer.PrivateDNSAddrV6().String()] = true
				}
			}
			// Update forwarders
			newForwarders := make([]string, 0)
			for _, forwarder := range s.meshforwarders {
				// Already registered mesh forwarder, keep it in the current position
				if _, ok := seen[forwarder]; ok {
					newForwarders = append(newForwarders, forwarder)
					seen[forwarder] = false
					continue
				}
			}
			// Add any forwarders not in the list yet
			for forwarder, toAdd := range seen {
				if toAdd {
					newForwarders = append(newForwarders, forwarder)
				}
			}
			s.log.Info("Updating meshdns forwarders", slog.Any("forwarders", newForwarders))
			s.meshforwarders = newForwarders
		}
		// Do an initial list to pre-populate the forwarders
		peers, err := dom.storage.MeshDB().Peers().List(context.Background(), storage.FilterByFeature(v1.Feature_FORWARD_MESH_DNS))
		if err != nil {
			s.log.Warn("Failed to lookup peers with forward meshdns", slog.String("error", err.Error()))
		}
		if len(peers) > 0 {
			updateForwarders(peers)
		}
		cancel, err := dom.storage.MeshDB().Peers().Subscribe(context.Background(), func([]types.MeshNode) {
			peers, err := dom.storage.MeshDB().Peers().List(context.Background(), storage.FilterByFeature(v1.Feature_FORWARD_MESH_DNS))
			if err != nil {
				s.log.Warn("Failed to lookup peers with forward meshdns", slog.String("error", err.Error()))
				return
			}
			if len(peers) == 0 {
				return
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			updateForwarders(peers)
		})
		if err != nil {
			return fmt.Errorf("failed to subscribe to storage/meshdb: %w", err)
		}
		mux.cancels = append(mux.cancels, cancel)
	}
	return nil
}
