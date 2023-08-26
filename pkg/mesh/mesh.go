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

// Package mesh contains the mesh store and related interfaces.
package mesh

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/discovery"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	"github.com/webmeshproj/webmesh/pkg/net"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
	"github.com/webmeshproj/webmesh/pkg/plugins"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins/basicauth"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins/ldap"
	"github.com/webmeshproj/webmesh/pkg/raft"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

var (
	// ErrNotOpen is returned when attempting to close a store that is not open.
	ErrNotOpen = fmt.Errorf("not open")
	// ErrOpen is returned when a store is already open.
	ErrOpen = fmt.Errorf("already open")
	// ErrNoLeader is returned when there is no Raft leader.
	ErrNoLeader = fmt.Errorf("no leader")
)

// Mesh is the connection to the Webmesh. It controls raft consensus, plugins,
// data storage, and WireGuard connections.
type Mesh interface {
	// ID returns the node ID.
	ID() string
	// Domain returns the domain of the mesh network.
	Domain() string
	// Open opens the connection to the mesh. This must be called before
	// other methods can be used.
	Open(ctx context.Context, features []v1.Feature) error
	// Ready returns a channel that will be closed when the mesh is ready.
	// Ready is defined as having a leader and knowing its address.
	Ready() <-chan struct{}
	// Close closes the connection to the mesh and shuts down the storage.
	Close() error
	// Dial opens a new gRPC connection to the given node.
	Dial(ctx context.Context, nodeID string) (*grpc.ClientConn, error)
	// DialLeader opens a new gRPC connection to the current Raft leader.
	DialLeader(context.Context) (*grpc.ClientConn, error)
	// Leader returns the current Raft leader ID.
	Leader() (string, error)
	// Storage returns a storage interface for use by the application.
	Storage() storage.MeshStorage
	// Raft returns the Raft interface.
	Raft() raft.Raft
	// Network returns the Network manager.
	Network() net.Manager
	// Plugins returns the Plugin manager.
	Plugins() plugins.Manager
	// AnnounceDHT announces the peer discovery service via DHT.
	AnnounceDHT(context.Context, *DiscoveryOptions) error
	// LeaveDHT leaves the peer discovery service for the given PSK.
	LeaveDHT(ctx context.Context, psk string) error
}

// New creates a new Mesh. You must call Open() on the returned mesh
// before it can be used.
func New(opts *Options) (Mesh, error) {
	return NewWithLogger(opts, slog.Default())
}

// NewWithLogger creates a new Mesh with the given logger. You must call
// Open() on the returned mesh before it can be used.
func NewWithLogger(opts *Options, log *slog.Logger) (Mesh, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	nodeID := opts.Mesh.NodeID
	var tlsConfig *tls.Config
	if !opts.TLS.Insecure {
		var err error
		tlsConfig, err = opts.TLSConfig()
		if err != nil {
			return nil, err
		}
	}
	log = log.With(slog.String("component", "mesh"))
	if nodeID == "" || nodeID == hostnameFlagDefault {
		nodeID = determineNodeID(log, tlsConfig, opts)
	}
	var peerUpdateGroup, routeUpdateGroup, dnsUpdateGroup errgroup.Group
	peerUpdateGroup.SetLimit(1)
	routeUpdateGroup.SetLimit(1)
	dnsUpdateGroup.SetLimit(1)
	st := &meshStore{
		opts:             opts,
		tlsConfig:        tlsConfig,
		nodeID:           nodeID,
		peerUpdateGroup:  &peerUpdateGroup,
		routeUpdateGroup: &routeUpdateGroup,
		dnsUpdateGroup:   &dnsUpdateGroup,
		log:              log.With(slog.String("node-id", string(nodeID))),
		kvSubCancel:      func() {},
		discoveries:      make(map[string]discovery.Discovery),
		closec:           make(chan struct{}),
	}
	return st, nil
}

func determineNodeID(log *slog.Logger, tlsConfig *tls.Config, opts *Options) string {
	// Check if we are using mTLS.
	if tlsConfig != nil {
		if len(tlsConfig.Certificates) > 0 {
			clientCert := tlsConfig.Certificates[0]
			leaf, err := x509.ParseCertificate(clientCert.Certificate[0])
			if err != nil {
				log.Warn("unable to parse client certificate to determine node ID", slog.String("error", err.Error()))
			} else {
				nodeID := leaf.Subject.CommonName
				log.Info("using CN as node ID", slog.String("node-id", nodeID))
				return nodeID
			}
		}
	}
	// Check if we are using auth
	if opts.Auth != nil {
		if opts.Auth.Basic != nil && opts.Auth.Basic.Username != "" {
			log.Info("using basic auth username as node ID",
				slog.String("node-id", opts.Auth.Basic.Username))
			return opts.Auth.Basic.Username
		}
		if opts.Auth.LDAP != nil && opts.Auth.LDAP.Username != "" {
			log.Info("using LDAP username as node ID",
				slog.String("node-id", opts.Auth.LDAP.Username))
			return opts.Auth.LDAP.Username
		}
	}
	// Try to retrieve the system hostname
	hostname, err := os.Hostname()
	if err != nil {
		log.Warn("unable to retrieve system hostname, generating random UUID for node ID",
			slog.String("error", err.Error()))
		return uuid.NewString()
	}
	log.Info("using system hostname as node ID", slog.String("node-id", string(hostname)))
	return hostname
}

type meshStore struct {
	open             atomic.Bool
	nodeID           string
	meshDomain       string
	opts             *Options
	raft             raft.Raft
	tlsConfig        *tls.Config
	plugins          plugins.Manager
	kvSubCancel      context.CancelFunc
	nw               net.Manager
	peerUpdateGroup  *errgroup.Group
	routeUpdateGroup *errgroup.Group
	dnsUpdateGroup   *errgroup.Group
	discoveries      map[string]discovery.Discovery
	discovermu       sync.Mutex
	closec           chan struct{}
	log              *slog.Logger
	// a flag set on test stores to indicate skipping certain operations
	testStore bool
}

// ID returns the node ID.
func (s *meshStore) ID() string {
	return string(s.nodeID)
}

// Domain returns the domain of the mesh network.
func (s *meshStore) Domain() string {
	return s.meshDomain
}

// Storage returns a storage interface for use by the application.
func (s *meshStore) Storage() storage.MeshStorage {
	return s.raft.Storage()
}

// Raft returns the Raft interface.
func (s *meshStore) Raft() raft.Raft {
	return s.raft
}

// Network returns the Network manager.
func (s *meshStore) Network() net.Manager {
	return s.nw
}

// Plugins returns the plugin manager. Note that the returned value
// may be nil if the store is not open.
func (s *meshStore) Plugins() plugins.Manager {
	return s.plugins
}

// Ready returns a channel that will be closed when the mesh is ready.
// Ready is defined as having a leader and knowing its address.
func (s *meshStore) Ready() <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		for {
			leader, err := s.Leader()
			if err != nil {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err = peers.New(s.Storage()).Get(ctx, leader)
			cancel()
			if err != nil {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return
		}
	}()
	return ch
}

// Leader returns the current Raft leader.
func (s *meshStore) Leader() (string, error) {
	if s.raft == nil || !s.open.Load() {
		return "", ErrNotOpen
	}
	return s.raft.LeaderID()
}

// DialLeader opens a new gRPC connection to the current Raft leader.
func (s *meshStore) DialLeader(ctx context.Context) (*grpc.ClientConn, error) {
	if s.raft == nil || !s.open.Load() {
		return nil, ErrNotOpen
	}
	leader, err := s.Leader()
	if err != nil {
		return nil, err
	}
	return s.Dial(ctx, leader)
}

// Dial opens a new gRPC connection to the given node.
func (s *meshStore) Dial(ctx context.Context, nodeID string) (*grpc.ClientConn, error) {
	if s.raft == nil || !s.open.Load() {
		return nil, ErrNotOpen
	}
	if !s.raft.IsVoter() && !s.raft.IsObserver() {
		// We are not a raft node and don't have a local copy of the DB.
		// A call to storage would cause a recursive call to this method.
		return s.dialWithWireguardPeers(ctx, nodeID)
	}
	return s.dialWithLocalStorage(ctx, nodeID)
}

func (s *meshStore) dialWithLocalStorage(ctx context.Context, nodeID string) (*grpc.ClientConn, error) {
	node, err := peers.New(s.Storage()).Get(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("get node private rpc address: %w", err)
	}
	if s.opts.Mesh.NoIPv4 {
		addr := node.PrivateRPCAddrV6()
		if !addr.IsValid() {
			return nil, fmt.Errorf("node %q has no private IPv6 address", nodeID)
		}
		return s.newGRPCConn(ctx, addr.String())
	}
	if s.opts.Mesh.NoIPv6 {
		addr := node.PrivateRPCAddrV4()
		if !addr.IsValid() {
			return nil, fmt.Errorf("node %q has no private IPv4 address", nodeID)
		}
		return s.newGRPCConn(ctx, addr.String())
	}
	// Fallback to whichever is valid if both are present (preferring IPv6)
	if node.PrivateRPCAddrV6().IsValid() {
		return s.newGRPCConn(ctx, node.PrivateRPCAddrV6().String())
	}
	return s.newGRPCConn(ctx, node.PrivateRPCAddrV4().String())
}

func (s *meshStore) dialWithWireguardPeers(ctx context.Context, nodeID string) (*grpc.ClientConn, error) {
	peers := s.Network().WireGuard().Peers()
	if len(peers) == 0 {
		return nil, fmt.Errorf("no wireguard peers")
	}
	var toDial *wireguard.Peer
	for id, peer := range peers {
		if !peer.RaftMember {
			// This method is only used for raft requests, so skip non-raft peers.
			// This may change in the future.
			continue
		}
		// An empty node ID means any peer is acceptable, but this should be more controlled
		// so retries can ensure a connection to a different peer.
		if nodeID == "" || id == nodeID {
			toDial = &peer
			break
		}
	}
	if toDial == nil {
		return nil, fmt.Errorf("no wireguard peer found for node %q", nodeID)
	}
	if s.opts.Mesh.NoIPv4 && toDial.PrivateIPv6.IsValid() {
		addr := netip.AddrPortFrom(toDial.PrivateIPv6.Addr(), uint16(toDial.GRPCPort))
		return s.newGRPCConn(ctx, addr.String())
	}
	if s.opts.Mesh.NoIPv6 && toDial.PrivateIPv4.IsValid() {
		addr := netip.AddrPortFrom(toDial.PrivateIPv4.Addr(), uint16(toDial.GRPCPort))
		return s.newGRPCConn(ctx, addr.String())
	}
	// Fallback to whichever is valid if both are present (preferring IPv6)
	if toDial.PrivateIPv6.IsValid() {
		addr := netip.AddrPortFrom(toDial.PrivateIPv6.Addr(), uint16(toDial.GRPCPort))
		return s.newGRPCConn(ctx, addr.String())
	}
	addr := netip.AddrPortFrom(toDial.PrivateIPv4.Addr(), uint16(toDial.GRPCPort))
	return s.newGRPCConn(ctx, addr.String())
}

func (s *meshStore) newGRPCConn(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	return grpc.DialContext(ctx, addr, s.grpcCreds(ctx)...)
}

func (s *meshStore) grpcCreds(ctx context.Context) []grpc.DialOption {
	log := context.LoggerFrom(ctx)
	var opts []grpc.DialOption
	if s.opts.TLS.Insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		// MTLS is included in the TLS config already if enabled.
		log.Debug("using TLS credentials")
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(s.tlsConfig)))
	}
	if s.opts.Auth != nil {
		if s.opts.Auth.Basic != nil {
			log.Debug("using basic auth credentials")
			opts = append(opts, basicauth.NewCreds(s.opts.Auth.Basic.Username, s.opts.Auth.Basic.Password))
		} else if s.opts.Auth.LDAP != nil {
			log.Debug("using LDAP auth credentials")
			opts = append(opts, ldap.NewCreds(s.opts.Auth.LDAP.Username, s.opts.Auth.LDAP.Password))
		}
	}
	return opts
}
