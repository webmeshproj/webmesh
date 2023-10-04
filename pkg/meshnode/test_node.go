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

package meshnode

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshnet"
	"github.com/webmeshproj/webmesh/pkg/meshnet/testutil"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport/libp2p"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport/tcp"
	"github.com/webmeshproj/webmesh/pkg/plugins"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/providers/raftstorage"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// NewTestNode creates a new test mesh and waits for it to be ready.
// The context is used to enforce startup timeouts.
func NewSingleNodeTestMesh(ctx context.Context) (Node, error) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	st := New(Config{
		NodeID: uuid.NewString(),
	})
	stor := st.(*meshStore)
	stor.testStore = true
	raftTransport, err := tcp.NewRaftTransport(st, tcp.RaftTransportOptions{
		Addr:    ":0",
		MaxPool: 1,
		Timeout: time.Second,
	})
	if err != nil {
		return nil, err
	}
	opts := raftstorage.NewOptions(st.ID(), raftTransport)
	opts.InMemory = true
	rft := raftstorage.NewProvider(opts)
	if err := rft.Start(ctx); err != nil {
		return nil, err
	}
	if err := stor.Connect(ctx, ConnectOptions{
		StorageProvider:      rft,
		GRPCAdvertisePort:    8443,
		MeshDNSAdvertisePort: 53,
		Bootstrap: &BootstrapOptions{
			Transport:            transport.NewNullBootstrapTransport(),
			IPv4Network:          "172.16.0.0/12",
			MeshDomain:           "webmesh.internal",
			Admin:                "admin",
			DisableRBAC:          false,
			DefaultNetworkPolicy: "accept",
		},
	}); err != nil {
		return nil, err
	}
	return stor, nil
}

// TestNode is a mesh node for testing.
type TestNode struct {
	transport.NodeDialer
	transport.LeaderDialer

	cfg        Config
	started    atomic.Bool
	storage    storage.Provider
	nw         meshnet.Manager
	plugins    plugins.Manager
	discovery  libp2p.Announcer
	nodeID     types.NodeID
	meshDomain string
	log        *slog.Logger
	mu         sync.Mutex
}

// NewTestNode creates a new test mesh node. It is not started and proper methods
// will return errors. A proper join round tripper must be supllied to the connect
// method.
func NewTestNode(opts Config) Node {
	return NewTestNodeWithLogger(slog.Default(), opts)
}

// NewTestNodeWithLogger creates a new test mesh node with a logger.
// It is not started and proper methods will return errors.
func NewTestNodeWithLogger(log *slog.Logger, opts Config) Node {
	return &TestNode{
		cfg:          opts,
		log:          log,
		nodeID:       types.NodeID(opts.NodeID),
		discovery:    &MockAnnouncer{},
		NodeDialer:   transport.NewNoOpNodeDialer(),
		LeaderDialer: transport.NewNoOpLeaderDialer(),
	}
}

// ID returns the node ID.
func (t *TestNode) ID() types.NodeID {
	return t.nodeID
}

// Dial dials a given address.
func (t *TestNode) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

// Started returns true if the mesh is started.
func (t *TestNode) Started() bool {
	return t.started.Load()
}

// Domain returns the domain of the mesh network.
func (t *TestNode) Domain() string {
	return t.meshDomain
}

// Key returns the private key used for WireGuard and libp2p connections.
func (t *TestNode) Key() crypto.PrivateKey {
	return t.cfg.Key
}

// Connect opens the connection to the mesh. This must be called before
// other methods can be used.
func (t *TestNode) Connect(ctx context.Context, opts ConnectOptions) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	encoded, err := t.cfg.Key.PublicKey().Encode()
	if err != nil {
		return err
	}
	wgeps := make([]string, 0)
	for _, ep := range opts.WireGuardEndpoints {
		wgeps = append(wgeps, ep.String())
	}
	routes := make([]string, 0)
	for _, r := range opts.Routes {
		routes = append(routes, r.String())
	}
	resp, err := opts.JoinRoundTripper.RoundTrip(ctx, &v1.JoinRequest{
		Id:                 t.nodeID.String(),
		PublicKey:          encoded,
		PrimaryEndpoint:    opts.PrimaryEndpoint.String(),
		WireguardEndpoints: wgeps,
		ZoneAwarenessID:    t.cfg.ZoneAwarenessID,
		AssignIPv4:         !t.cfg.DisableIPv4,
		PreferStorageIPv6:  !t.cfg.DisableIPv6,
		AsVoter:            opts.RequestVote,
		AsObserver:         opts.RequestObserver,
		Routes:             routes,
		DirectPeers:        opts.DirectPeers,
		Features:           opts.Features,
	})
	if err != nil {
		return fmt.Errorf("mock node join request: %w", err)
	}
	var addrv4, addrv6, netv4, netv6 netip.Prefix
	if !t.cfg.DisableIPv4 {
		if resp.GetAddressIPv4() != "" {
			addrv4, err = netip.ParsePrefix(resp.GetAddressIPv4())
			if err != nil {
				return fmt.Errorf("mock node join request: %w", err)
			}
		}
		if resp.GetNetworkIPv4() != "" {
			netv4, err = netip.ParsePrefix(resp.GetNetworkIPv4())
			if err != nil {
				return fmt.Errorf("mock node join request: %w", err)
			}
		}
	}
	if !t.cfg.DisableIPv6 {
		if resp.GetAddressIPv6() != "" {
			addrv6, err = netip.ParsePrefix(resp.GetAddressIPv6())
			if err != nil {
				return fmt.Errorf("mock node join request: %w", err)
			}
		}
		if resp.GetNetworkIPv6() != "" {
			netv6, err = netip.ParsePrefix(resp.GetNetworkIPv6())
			if err != nil {
				return fmt.Errorf("mock node join request: %w", err)
			}
		}
	}
	t.storage = opts.StorageProvider
	t.plugins = plugins.NewManagerWithDB(opts.StorageProvider)
	t.meshDomain = resp.GetMeshDomain()
	t.nw = testutil.NewManager(meshnet.Options{
		InterfaceName:       opts.NetworkOptions.InterfaceName,
		ListenPort:          opts.NetworkOptions.ListenPort,
		Modprobe:            opts.NetworkOptions.Modprobe,
		PersistentKeepAlive: opts.NetworkOptions.PersistentKeepAlive,
		ForceTUN:            opts.NetworkOptions.ForceTUN,
		MTU:                 opts.NetworkOptions.MTU,
		ZoneAwarenessID:     t.cfg.ZoneAwarenessID,
		DisableIPv4:         t.cfg.DisableIPv4,
		DisableIPv6:         t.cfg.DisableIPv6,
	}, t.nodeID)
	err = t.nw.Start(ctx, meshnet.StartOptions{
		Key:       t.cfg.Key,
		AddressV4: addrv4,
		AddressV6: addrv6,
		NetworkV4: netv4,
		NetworkV6: netv6,
	})
	if err != nil {
		return fmt.Errorf("mock node start network manager: %w", err)
	}
	t.started.Store(true)
	return nil
}

// Ready returns a channel that will be closed when the mesh is ready.
// Ready is defined as having a leader and knowing its address.
func (t *TestNode) Ready() <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		for !t.Started() {
		}
	}()
	return ch
}

// Close closes the connection to the mesh and shuts down the storage.
func (t *TestNode) Close(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	defer t.started.Store(false)
	if t.storage != nil {
		if err := t.storage.Close(); err != nil {
			t.log.Error("Failed to close storage", slog.String("error", err.Error()))
		}
	}
	return t.nw.Close(ctx)
}

// Credentials returns the gRPC credentials to use for dialing the mesh.
func (t *TestNode) Credentials() []grpc.DialOption {
	return nil
}

// LeaderID returns the current Raft leader ID.
func (t *TestNode) LeaderID() (types.NodeID, error) {
	return t.nodeID, nil
}

// Storage returns the underlying storage provider.
func (t *TestNode) Storage() storage.Provider {
	return t.storage
}

// Network returns the Network manager.
func (t *TestNode) Network() meshnet.Manager {
	return t.nw
}

// Plugins returns the Plugin manager.
func (t *TestNode) Plugins() plugins.Manager {
	return t.plugins
}

// Discovery returns the interface libp2p.Announcer for announcing
// the mesh to the discovery service.
func (t *TestNode) Discovery() libp2p.Announcer {
	return t.discovery
}

// MockAnnouncer is a mock announcer that tracks state internally but does
// not perform any actual announcements.
type MockAnnouncer struct {
	announcements map[string]struct{}
	mu            sync.Mutex
}

// AnnounceToDHT should announce the join protocol to the DHT,
// such that it can be used by a libp2p transport.JoinRoundTripper.
func (m *MockAnnouncer) AnnounceToDHT(ctx context.Context, opts libp2p.AnnounceOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.announcements == nil {
		m.announcements = make(map[string]struct{})
	}
	m.announcements[opts.Rendezvous] = struct{}{}
	return nil
}

// LeaveDHT should remove the join protocol from the DHT for the
// given rendezvous string.
func (m *MockAnnouncer) LeaveDHT(ctx context.Context, rendezvous string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.announcements, rendezvous)
	return nil
}
