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

// Package meshnode contains the mesh node and related interfaces.
package meshnode

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshnet"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/meshnet/wireguard"
	"github.com/webmeshproj/webmesh/pkg/plugins"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

var (
	// ErrNotOpen is returned when attempting to close a store that is not open.
	ErrNotOpen = fmt.Errorf("not open")
	// ErrOpen is returned when a store is already open.
	ErrOpen = fmt.Errorf("already open")
	// ErrNoLeader is returned when there is no Raft leader.
	ErrNoLeader = fmt.Errorf("no leader")
)

// Node is the connection to the Webmesh. It controls raft consensus, plugins,
// data storage, and WireGuard connections.
type Node interface {
	// Dialer is the dialer for all connections.
	transport.Dialer
	// NodeDialer is the dialer for node RPC connections.
	transport.NodeDialer
	// LeaderDialer is the dialer for leader RPC connections.
	transport.LeaderDialer

	// ID returns the node ID.
	ID() types.NodeID
	// Started returns true if the mesh is started.
	Started() bool
	// Domain returns the domain of the mesh network.
	Domain() string
	// Key returns the private key used for WireGuard and libp2p connections.
	Key() crypto.PrivateKey
	// Connect opens the connection to the mesh. This must be called before
	// other methods can be used.
	Connect(ctx context.Context, opts ConnectOptions) error
	// Ready returns a channel that will be closed when the mesh is ready.
	// Ready is defined as having a leader and knowing its address.
	Ready() <-chan struct{}
	// Close closes the connection to the mesh and shuts down the storage.
	Close(ctx context.Context) error
	// Credentials returns the gRPC credentials to use for dialing the mesh.
	Credentials() []grpc.DialOption
	// LeaderID returns the current Raft leader ID.
	LeaderID() (types.NodeID, error)
	// Storage returns the underlying storage provider.
	Storage() storage.Provider
	// Network returns the Network manager.
	Network() meshnet.Manager
	// Plugins returns the Plugin manager.
	Plugins() plugins.Manager
}

// Config contains the configurations for a new mesh connection.
type Config struct {
	// NodeID is the node ID to use. If empty, the one from the raft
	// instance will be used.
	NodeID string
	// Credentials are gRPC credentials to use when dialing other nodes
	// in the mesh.
	Credentials []grpc.DialOption
	// Key is the private key to use for WireGuard and libp2p connections.
	// This can be nil, in which case one will be generated when Connect
	// is called.
	Key crypto.PrivateKey
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
	// LocalDNSOnly will only use the local MeshDNS server for DNS
	// resolution. This is only applicable when UseMeshDNS is true.
	LocalDNSOnly bool
	// DisableIPv4 is true if IPv4 should be disabled.
	DisableIPv4 bool
	// DisableIPv6 is true if IPv6 should be disabled.
	DisableIPv6 bool
	// DisableDefaultIPAM disables the default IPAM plugin.
	DisableDefaultIPAM bool
	// DefaultIPAMStaticIPv4 is a map of node names to IPv4 addresses.
	DefaultIPAMStaticIPv4 map[string]string
}

// New creates a new Mesh. You must call Open() on the returned mesh
// before it can be used.
func New(opts Config) Node {
	return NewWithLogger(slog.Default(), opts)
}

// NewWithLogger creates a new Mesh with the given logger. You must call
// Open() on the returned mesh before it can be used.
func NewWithLogger(log *slog.Logger, opts Config) Node {
	log = log.With(slog.String("component", "mesh"))
	var peerUpdateGroup, routeUpdateGroup, dnsUpdateGroup errgroup.Group
	peerUpdateGroup.SetLimit(1)
	routeUpdateGroup.SetLimit(1)
	dnsUpdateGroup.SetLimit(1)
	st := &meshStore{
		opts:             opts,
		nodeID:           opts.NodeID,
		key:              opts.Key,
		peerUpdateGroup:  &peerUpdateGroup,
		routeUpdateGroup: &routeUpdateGroup,
		dnsUpdateGroup:   &dnsUpdateGroup,
		log:              log.With(slog.String("node-id", string(opts.NodeID))),
		kvSubCancel:      func() {},
		closec:           make(chan struct{}),
	}
	return st
}

type meshStore struct {
	open             atomic.Bool
	nodeID           string
	meshDomain       string
	opts             Config
	key              crypto.PrivateKey
	storage          storage.Provider
	plugins          plugins.Manager
	kvSubCancel      context.CancelFunc
	nw               meshnet.Manager
	peerUpdateGroup  *errgroup.Group
	routeUpdateGroup *errgroup.Group
	dnsUpdateGroup   *errgroup.Group
	leaveRTT         transport.LeaveRoundTripper
	closec           chan struct{}
	log              *slog.Logger
	mu               sync.Mutex
	// a flag set on test stores to indicate skipping certain operations
	testStore bool
}

// ID returns the node ID.
func (s *meshStore) ID() types.NodeID {
	return types.NodeID(s.nodeID)
}

// Started returns true if the mesh is started.
func (s *meshStore) Started() bool {
	return s.open.Load()
}

// Key returns the private key used for WireGuard and libp2p connections.
func (s *meshStore) Key() crypto.PrivateKey {
	return s.key
}

// Domain returns the domain of the mesh network.
func (s *meshStore) Domain() string {
	return s.meshDomain
}

// Storage returns a storage interface for use by the application.
func (s *meshStore) Storage() storage.Provider {
	return s.storage
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
			ctx, cancel := context.WithTimeout(context.WithLogger(context.Background(), s.log), 5*time.Second)
			leader, err := s.getLeader(ctx)
			cancel()
			if err != nil {
				s.log.Debug("Unable to fetch current leader", slog.String("leader", leader.String()), slog.String("error", err.Error()))
				time.Sleep(time.Millisecond * 500)
				continue
			}
			if leader.GetId() == "" || leader.GetAddress() == "" {
				s.log.Debug("Leader not ready", slog.String("leader", leader.String()))
				time.Sleep(time.Millisecond * 500)
				continue
			}
			return
		}
	}()
	return ch
}

// Leader returns the current network leader.
func (s *meshStore) LeaderID() (types.NodeID, error) {
	leader, err := s.getLeader(context.WithLogger(context.Background(), s.log))
	if err != nil {
		return "", fmt.Errorf("get leader: %w", err)
	}
	return types.NodeID(leader.GetId()), nil
}

// getLeader returns the current network leader.
func (s *meshStore) getLeader(ctx context.Context) (types.StoragePeer, error) {
	if s.storage == nil || !s.open.Load() {
		return types.StoragePeer{}, ErrNotOpen
	}
	leader, err := s.storage.Consensus().GetLeader(ctx)
	if err != nil {
		return types.StoragePeer{}, fmt.Errorf("get leader: %w", err)
	}
	return leader, nil
}

// Dial is a generic dial method.
func (s *meshStore) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if s.storage == nil || !s.open.Load() {
		return nil, ErrNotOpen
	}
	return s.nw.Dial(ctx, network, address)
}

// DialLeader opens a new gRPC connection to the current Raft leader.
func (s *meshStore) DialLeader(ctx context.Context) (*grpc.ClientConn, error) {
	leader, err := s.LeaderID()
	if err != nil {
		return nil, err
	}
	return s.DialNode(ctx, leader)
}

// Dial opens a new gRPC connection to the given node.
func (s *meshStore) DialNode(ctx context.Context, nodeID types.NodeID) (*grpc.ClientConn, error) {
	if s.storage == nil || !s.open.Load() {
		return nil, ErrNotOpen
	}
	if !s.storage.Consensus().IsMember() {
		// We are not a raft node and don't have a local copy of the DB.
		// A call to storage would cause a recursive call to this method.
		return s.dialWithWireguardPeers(ctx, nodeID)
	}
	return s.dialWithLocalStorage(ctx, nodeID)
}

func (s *meshStore) Credentials() []grpc.DialOption {
	return s.opts.Credentials
}

func (s *meshStore) dialWithLocalStorage(ctx context.Context, nodeID types.NodeID) (*grpc.ClientConn, error) {
	var node types.MeshNode
	var err error
	if nodeID == "" {
		// This is a request for any storage providing node.
		nodes, err := s.Storage().MeshDB().Peers().List(ctx, storage.FilterByFeature(v1.Feature_STORAGE_PROVIDER))
		if err != nil {
			return nil, fmt.Errorf("list storage providers: %w", err)
		}
		if len(nodes) == 0 {
			return nil, fmt.Errorf("no storage providers found")
		}
		node = nodes[0]
	} else {
		node, err = s.Storage().MeshDB().Peers().Get(ctx, nodeID)
		if err != nil {
			return nil, fmt.Errorf("get node private rpc address: %w", err)
		}
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

func (s *meshStore) dialWithWireguardPeers(ctx context.Context, nodeID types.NodeID) (*grpc.ClientConn, error) {
	peers := s.Network().WireGuard().Peers()
	if len(peers) == 0 {
		return nil, fmt.Errorf("no wireguard peers")
	}
	var toDial *wireguard.Peer
	for id, peer := range peers {
		if !peer.StorageProvider {
			// This method is only used for storage requests, so skip non-storage-providing peers.
			// This may change in the future.
			continue
		}
		// An empty node ID means any storage peer is acceptable, but this should be more controlled
		// so retries can ensure a connection to a different peer.
		if nodeID == "" || id == nodeID.String() {
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
