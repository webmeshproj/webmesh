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
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	meshnet "github.com/webmeshproj/webmesh/pkg/net"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/net/transport/libp2p"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
	"github.com/webmeshproj/webmesh/pkg/plugins"
	"github.com/webmeshproj/webmesh/pkg/raft"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// DefaultMeshDomain is the default domain for the mesh network.
const DefaultMeshDomain = "webmesh.internal"

// DefaultIPv4Network is the default IPv4 network for the mesh.
const DefaultIPv4Network = "172.16.0.0/12"

// DefaultNetworkPolicy is the default network policy for the mesh.
const DefaultNetworkPolicy = "accept"

// DefaultBootstrapListenAddress is the default listen address for the bootstrap transport.
const DefaultBootstrapListenAddress = "[::]:9001"

// DefaultBootstrapPort is the default port for the bootstrap transport.
const DefaultBootstrapPort = 9001

// DefaultMeshAdmin is the default mesh admin node ID.
const DefaultMeshAdmin = "admin"

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
	// Dialer is the dialer for all connections.
	transport.Dialer
	// NodeDialer is the dialer for node connections.
	transport.NodeDialer
	// LeaderDialer is the dialer for leader connections.
	transport.LeaderDialer

	// ID returns the node ID.
	ID() string
	// Domain returns the domain of the mesh network.
	Domain() string
	// Connect opens the connection to the mesh. This must be called before
	// other methods can be used.
	Connect(ctx context.Context, opts ConnectOptions) error
	// Ready returns a channel that will be closed when the mesh is ready.
	// Ready is defined as having a leader and knowing its address.
	Ready() <-chan struct{}
	// Close closes the connection to the mesh and shuts down the storage.
	Close() error
	// Credentials returns the gRPC credentials to use for dialing the mesh.
	Credentials() []grpc.DialOption
	// LeaderID returns the current Raft leader ID.
	LeaderID() (string, error)
	// Storage returns a storage interface for use by the application.
	Storage() storage.MeshStorage
	// Raft returns the Raft interface. This will be nil if connect has not
	// been called.
	Raft() raft.Raft
	// Network returns the Network manager.
	Network() meshnet.Manager
	// Plugins returns the Plugin manager.
	Plugins() plugins.Manager
	// AnnounceDHT announces the peer discovery service via DHT.
	AnnounceDHT(context.Context, libp2p.JoinAnnounceOptions) error
	// LeaveDHT leaves the peer discovery service for the given PSK.
	LeaveDHT(ctx context.Context, psk string) error
}

// Config contains the configurations for a new mesh connection.
type Config struct {
	// NodeID is the node ID to use. If empty, the one from the raft
	// instance will be used.
	NodeID string
	// Credentials are gRPC credentials to use when dialing the mesh.
	Credentials []grpc.DialOption
	// HeartbeatPurgeThreshold is the number of failed heartbeats before
	// assuming a peer is offline. This is only applicable when currently
	// the leader of the raft group.
	HeartbeatPurgeThreshold int
	// ZoneAwarenessID is an to use with zone-awareness to determine
	// peers in the same LAN segment.
	ZoneAwarenessID string
	// UseMeshDNS will attempt to set the system DNS to any discovered
	// DNS servers. This is only applicable when not serving MeshDNS
	// ourselves.
	UseMeshDNS bool
	// LocalMeshDNSAddr is the address MeshDNS is listening on locally.
	LocalMeshDNSAddr string
	// WireGuardKeyFile is a location to store and reuse a WireGuard key.
	// This is optional. If specified and the file does not exist, one will
	// be generated and stored there.
	WireGuardKeyFile string
	// KeyRotationInterval is the interval to rotate WireGuard keys. This is
	// only applicable when a WireguardKeyFile is specified. Otherwise a new
	// one will be generated on each startup.
	KeyRotationInterval time.Duration
	// DisableIPv4 is true if IPv4 should be disabled.
	DisableIPv4 bool
	// DisableIPv6 is true if IPv6 should be disabled.
	DisableIPv6 bool
}

// New creates a new Mesh. You must call Open() on the returned mesh
// before it can be used.
func New(opts Config) Mesh {
	return NewWithLogger(slog.Default(), opts)
}

// NewWithLogger creates a new Mesh with the given logger. You must call
// Open() on the returned mesh before it can be used.
func NewWithLogger(log *slog.Logger, opts Config) Mesh {
	log = log.With(slog.String("component", "mesh"))
	var peerUpdateGroup, routeUpdateGroup, dnsUpdateGroup errgroup.Group
	peerUpdateGroup.SetLimit(1)
	routeUpdateGroup.SetLimit(1)
	dnsUpdateGroup.SetLimit(1)
	st := &meshStore{
		opts:             opts,
		nodeID:           opts.NodeID,
		peerUpdateGroup:  &peerUpdateGroup,
		routeUpdateGroup: &routeUpdateGroup,
		dnsUpdateGroup:   &dnsUpdateGroup,
		log:              log.With(slog.String("node-id", string(opts.NodeID))),
		kvSubCancel:      func() {},
		discoveries:      make(map[string]io.Closer),
		closec:           make(chan struct{}),
	}
	return st
}

type meshStore struct {
	open             atomic.Bool
	nodeID           string
	meshDomain       string
	opts             Config
	raft             raft.Raft
	plugins          plugins.Manager
	kvSubCancel      context.CancelFunc
	nw               meshnet.Manager
	peerUpdateGroup  *errgroup.Group
	routeUpdateGroup *errgroup.Group
	dnsUpdateGroup   *errgroup.Group
	discoveries      map[string]io.Closer
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
func (s *meshStore) Network() meshnet.Manager {
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
			leader, err := s.LeaderID()
			if err != nil {
				s.log.Debug("waiting for leader", slog.String("error", err.Error()))
				time.Sleep(time.Millisecond * 500)
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, err = peers.New(s.Storage()).Get(ctx, leader)
			cancel()
			if err != nil {
				s.log.Debug("waiting for leader", slog.String("leader", leader), slog.String("error", err.Error()))
				time.Sleep(time.Millisecond * 500)
				continue
			}
			return
		}
	}()
	return ch
}

// Leader returns the current Raft leader.
func (s *meshStore) LeaderID() (string, error) {
	if s.raft == nil || !s.open.Load() {
		return "", ErrNotOpen
	}
	return s.raft.LeaderID()
}

// Dial is a generic dial method.
func (s *meshStore) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if s.raft == nil || !s.open.Load() {
		return nil, ErrNotOpen
	}
	return s.nw.Dial(ctx, network, address)
}

// DialLeader opens a new gRPC connection to the current Raft leader.
func (s *meshStore) DialLeader(ctx context.Context) (*grpc.ClientConn, error) {
	if s.raft == nil || !s.open.Load() {
		return nil, ErrNotOpen
	}
	leader, err := s.LeaderID()
	if err != nil {
		return nil, err
	}
	return s.DialNode(ctx, leader)
}

// Dial opens a new gRPC connection to the given node.
func (s *meshStore) DialNode(ctx context.Context, nodeID string) (*grpc.ClientConn, error) {
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

func (s *meshStore) Credentials() []grpc.DialOption {
	return s.opts.Credentials
}

func (s *meshStore) dialWithLocalStorage(ctx context.Context, nodeID string) (*grpc.ClientConn, error) {
	node, err := peers.New(s.Storage()).Get(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("get node private rpc address: %w", err)
	}
	if s.opts.DisableIPv4 {
		addr := node.PrivateRPCAddrV6()
		if !addr.IsValid() {
			return nil, fmt.Errorf("node %q has no private IPv6 address", nodeID)
		}
		return s.newGRPCConn(ctx, addr.String())
	}
	if s.opts.DisableIPv6 {
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
	if s.opts.DisableIPv4 && toDial.PrivateIPv6.IsValid() {
		addr := netip.AddrPortFrom(toDial.PrivateIPv6.Addr(), uint16(toDial.GRPCPort))
		return s.newGRPCConn(ctx, addr.String())
	}
	if s.opts.DisableIPv6 && toDial.PrivateIPv4.IsValid() {
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
	return grpc.DialContext(ctx, addr, s.Credentials()...)
}
