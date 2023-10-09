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

// Package transport defines the libp2p webmesh transport.
package transport

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/transport"
	ma "github.com/multiformats/go-multiaddr"
	mnet "github.com/multiformats/go-multiaddr/net"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/config"
	"github.com/webmeshproj/webmesh/pkg/context"
	wmcrypto "github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/libp2p/protocol"
	p2putil "github.com/webmeshproj/webmesh/pkg/libp2p/util"
	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/meshnode"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// TransportBuilder is the signature of a function that builds a webmesh transport.
type TransportBuilder func(upgrader transport.Upgrader, host host.Host, rcmgr network.ResourceManager, privKey crypto.PrivKey) (Transport, error)

// Transport is the webmesh transport.
type Transport interface {
	// Closer for the underlying transport that shuts down the webmesh node.
	io.Closer
	// Transport is the underlying libp2p Transport.
	transport.Transport
	// Resolver is a resolver that uses the mesh storage to lookup peers.
	transport.Resolver
}

var _ Transport = (*WebmeshTransport)(nil)

// Options are the options for the webmesh transport.
type Options struct {
	// Config is the webmesh config.
	Config *config.Config
	// LogLevel is the log level for the webmesh transport.
	LogLevel string
	// StartTimeout is the timeout for starting the webmesh node.
	StartTimeout time.Duration
	// StopTimeout is the timeout for stopping the webmesh node.
	StopTimeout time.Duration
	// ListenTimeout is the timeout for starting a listener on the webmesh node.
	ListenTimeout time.Duration
	// Logger is the logger to use for the webmesh transport.
	// If nil, an empty logger will be used.
	Logger *slog.Logger
}

// New returns a new webmesh transport builder.
func New(opts Options) (TransportBuilder, *WebmeshTransport) {
	if opts.Config == nil {
		panic("config is required")
	}
	if opts.Logger == nil {
		opts.Logger = logging.NewLogger("", "")
	}
	rt := &WebmeshTransport{
		opts: opts,
		conf: opts.Config.ShallowCopy(),
		log:  opts.Logger.With("component", "webmesh-transport"),
	}
	return func(tu transport.Upgrader, host host.Host, rcmgr network.ResourceManager, privKey crypto.PrivKey) (Transport, error) {
		key, err := p2putil.ToWebmeshPrivateKey(privKey)
		if err != nil {
			return nil, err
		}
		rt.key = key
		rt.host = host
		rt.tu = tu
		rt.rcmgr = rcmgr
		return rt, nil
	}, rt
}

// WebmeshTransport is the webmesh libp2p transport. It must be used with a webmesh keypair and security transport.
type WebmeshTransport struct {
	started atomic.Bool
	opts    Options
	conf    *config.Config
	node    meshnode.Node
	svcs    *services.Server
	host    host.Host
	key     wmcrypto.PrivateKey
	tu      transport.Upgrader
	rcmgr   network.ResourceManager
	log     *slog.Logger
	laddrs  []ma.Multiaddr
	mu      sync.Mutex
}

// BroadcastAddrs implements AddrsFactory on top of this transport. It automatically appends
// our webmesh ID and any DNS addresses we have to the list of addresses.
func (t *WebmeshTransport) BroadcastAddrs(addrs []ma.Multiaddr) []ma.Multiaddr {
	t.mu.Lock()
	defer t.mu.Unlock()
	id, err := peer.IDFromPrivateKey(t.key)
	if err != nil {
		t.log.Error("Failed to get peer ID from private key", "error", err.Error())
		return addrs
	}
	webmeshSec := protocol.WithPeerID(id)
	if t.conf.Discovery.Announce {
		webmeshSec = protocol.WithPeerIDAndRendezvous(id, t.conf.Discovery.Rendezvous)
	}
	var out []ma.Multiaddr
	for _, addr := range addrs {
		out = append(out, ma.Join(addr, webmeshSec))
	}
	if t.started.Load() {
		// Add our DNS addresses
		for _, addr := range addrs {
			var proto string
			port, err := addr.ValueForProtocol(ma.P_TCP)
			if err != nil {
				port, err = addr.ValueForProtocol(ma.P_UDP)
				if err != nil {
					continue
				}
				proto = "udp"
			} else {
				proto = "tcp"
			}
			dnsaddr, err := ma.NewMultiaddr(fmt.Sprintf("/dns6/%s.%s", t.node.ID(), strings.TrimSuffix(t.node.Domain(), ".")))
			if err != nil {
				continue
			}
			addrs = append(addrs, ma.Join(dnsaddr, ma.StringCast(fmt.Sprintf("/%s/%s", proto, port)), webmeshSec))
			dnsaddr, err = ma.NewMultiaddr(fmt.Sprintf("/dns4/%s.%s", t.node.ID(), strings.TrimSuffix(t.node.Domain(), ".")))
			if err != nil {
				continue
			}
			addrs = append(addrs, ma.Join(dnsaddr, ma.StringCast(fmt.Sprintf("/%s/%s", proto, port)), webmeshSec))
		}
	}
	return out
}

// Dial dials a remote peer. It should try to reuse local listener
// addresses if possible, but it may choose not to.
func (t *WebmeshTransport) Dial(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (transport.CapableConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.started.Load() {
		return nil, p2putil.ErrNotStarted
	}
	ctx = context.WithLogger(ctx, t.log)
	ipver := "ip4"
	proto := "tcp"
	_, err := raddr.ValueForProtocol(ma.P_TCP)
	if err != nil {
		_, err = raddr.ValueForProtocol(ma.P_UDP)
		if err != nil {
			return nil, fmt.Errorf("failed to get L4 protocol from dial address: %w", err)
		}
		proto = "udp"
	}
	_, err = raddr.ValueForProtocol(ma.P_IP6)
	if err == nil {
		ipver = "ip6"
	}
	_, err = raddr.ValueForProtocol(ma.P_DNS6)
	if err == nil {
		ipver = "ip6"
	}
	var localAddr netip.Addr
	switch ipver {
	case "ip4":
		localAddr = t.node.Network().WireGuard().AddressV4().Addr()
	case "ip6":
		localAddr = t.node.Network().WireGuard().AddressV6().Addr()
	}
	dialer := mnet.Dialer{
		LocalAddr: ma.StringCast(fmt.Sprintf("/%s/%s/%s/0", ipver, localAddr.String(), proto)),
	}
	t.log.Debug("Dialing remote peer", "peer", p.String(), "raddr", raddr.String())
	connScope, err := t.rcmgr.OpenConnection(network.DirOutbound, false, raddr)
	if err != nil {
		t.log.Error("Failed to open connection", "error", err.Error(), "peer", p.String(), "raddr", raddr.String())
		return nil, fmt.Errorf("failed to open connection: %w", err)
	}
	defer connScope.Done()
	c, err := dialer.DialContext(ctx, raddr)
	if err != nil {
		t.log.Error("Failed to dial remote peer", "error", err.Error(), "peer", p.String(), "raddr", raddr.String())
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	u, err := t.tu.Upgrade(ctx, t, c, network.DirOutbound, p, connScope)
	if err != nil {
		t.log.Error("Failed to upgrade connection", "error", err.Error(), "peer", p.String(), "raddr", raddr.String())
		return nil, fmt.Errorf("failed to upgrade connection: %w", err)
	}
	return u, nil
}

// CanDial returns true if this transport knows how to dial the given
// multiaddr.
//
// Returning true does not guarantee that dialing this multiaddr will
// succeed. This function should *only* be used to preemptively filter
// out addresses that we can't dial.
func (t *WebmeshTransport) CanDial(addr ma.Multiaddr) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.started.Load() {
		return false
	}
	// For now we say we can dial any webmesh address
	_, err := addr.ValueForProtocol(protocol.P_WEBMESH)
	if err == nil {
		return true
	}
	// Same goes for DNS4/DNS6
	_, err = addr.ValueForProtocol(ma.P_DNS4)
	if err == nil {
		return true
	}
	_, err = addr.ValueForProtocol(ma.P_DNS6)
	if err == nil {
		return true
	}
	// We can do ip4/ip6 dialing if they are within our network.
	ip4addr, err := addr.ValueForProtocol(ma.P_IP4)
	if err == nil {
		addr, err := netip.ParseAddr(ip4addr)
		if err != nil {
			return false
		}
		return t.node.Network().NetworkV4().Contains(addr)
	}
	ip6addr, err := addr.ValueForProtocol(ma.P_IP6)
	if err == nil {
		addr, err := netip.ParseAddr(ip6addr)
		if err != nil {
			return false
		}
		return t.node.Network().NetworkV6().Contains(addr)
	}
	return false
}

// Listen listens on the passed multiaddr.
func (t *WebmeshTransport) Listen(laddr ma.Multiaddr) (transport.Listener, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ctx := context.WithLogger(context.Background(), t.log)
	if t.opts.ListenTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.opts.ListenTimeout)
		defer cancel()
	}
	if !t.started.Load() {
		// We use the background context to not let the listen timeout
		// interfere with the start timeout
		logLevel := t.opts.Config.Global.LogLevel
		logFormat := t.opts.Config.Global.LogFormat
		node, err := t.startNode(context.WithLogger(context.Background(), logging.NewLogger(logLevel, logFormat)), laddr)
		if err != nil {
			return nil, fmt.Errorf("failed to start node: %w", err)
		}
		t.node = node
		t.started.Store(true)
	}
	// Find the port requested in the listener address
	port, err := laddr.ValueForProtocol(ma.P_TCP)
	if err != nil {
		return nil, fmt.Errorf("failed to get port from listener address: %w", err)
	}
	// We automatically set the listening address to our local IPv6 address
	if _, err := laddr.ValueForProtocol(ma.P_IP6); err == nil {
		lnetaddr := t.node.Network().WireGuard().AddressV6().Addr()
		laddr, err = ma.NewMultiaddr(fmt.Sprintf("/ip6/%s/tcp/%s", lnetaddr, port))
		if err != nil {
			return nil, fmt.Errorf("failed to create listener address: %w", err)
		}
	} else {
		lnetaddr := t.node.Network().WireGuard().AddressV4().Addr()
		laddr, err = ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%s", lnetaddr, port))
		if err != nil {
			return nil, fmt.Errorf("failed to create listener address: %w", err)
		}
	}
	t.log.Info("Listening for webmesh connections", "address", laddr.String())
	lis, err := mnet.Listen(laddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}
	// Register our listeners to the webmesh cluster so they can help
	// others find us
	err = t.registerMultiaddrsForListener(ctx, lis)
	if err != nil {
		defer lis.Close()
		return nil, fmt.Errorf("failed to register multiaddrs: %w", err)
	}
	return t.tu.UpgradeListener(t, lis), nil
}

// Resolve attempts to resolve the given multiaddr to a list of addresses.
func (t *WebmeshTransport) Resolve(ctx context.Context, maddr ma.Multiaddr) ([]ma.Multiaddr, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.started.Load() {
		return nil, p2putil.ErrNotStarted
	}
	ctx = context.WithLogger(ctx, t.log)
	t.log.Debug("Resolving multiaddr", "multiaddr", maddr.String())
	if value, err := maddr.ValueForProtocol(ma.P_IP4); err == nil {
		// Already resolved if in network
		val, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ip4 address: %w", err)
		}
		if t.node.Network().InNetwork(val) {
			return []ma.Multiaddr{maddr}, nil
		}
		return nil, fmt.Errorf("ipv4 address not in network")
	}
	if value, err := maddr.ValueForProtocol(ma.P_IP6); err == nil {
		// Already resolved if in network
		val, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ip6 address: %w", err)
		}
		if t.node.Network().InNetwork(val) {
			return []ma.Multiaddr{maddr}, nil
		}
		return nil, fmt.Errorf("ipv6 address not in network")
	}
	// If it's a DNS address, we can try using our local MeshDNS to resolve it.
	value, err := maddr.ValueForProtocol(ma.P_DNS6)
	if err == nil {
		fqdn := strings.TrimSuffix(value, ".")
		dom := strings.TrimSuffix(t.node.Domain(), ".")
		nodeID := strings.TrimSuffix(strings.TrimSuffix(fqdn, dom), ".")
		if nodeID == t.node.ID().String() {
			t.log.Warn("Cannot resolve self")
			return nil, fmt.Errorf("cannot resolve self")
		}
		t.log.Debug("Resolving DNS6 address", "fqdn", fqdn, "nodeID", nodeID)
		peer, err := t.node.Storage().MeshDB().Peers().Get(ctx, types.NodeID(nodeID))
		if err != nil {
			t.log.Error("Failed to get peer", "error", err.Error(), "nodeID", nodeID)
			return nil, fmt.Errorf("failed to get peer: %w", err)
		}
		return peerToIPMultiaddrs(peer, maddr)
	}
	// We can do the same for DNS4 addresses
	value, err = maddr.ValueForProtocol(ma.P_DNS4)
	if err == nil {
		fqdn := strings.TrimSuffix(value, ".")
		dom := strings.TrimSuffix(t.node.Domain(), ".")
		nodeID := strings.TrimSuffix(strings.TrimSuffix(fqdn, dom), ".")
		if nodeID == t.node.ID().String() {
			t.log.Warn("Cannot resolve self")
			return nil, fmt.Errorf("cannot resolve self")
		}
		t.log.Debug("Resolving DNS4 address", "fqdn", fqdn, "nodeID", nodeID)
		peer, err := t.node.Storage().MeshDB().Peers().Get(ctx, types.NodeID(nodeID))
		if err != nil {
			t.log.Error("Failed to get peer", "error", err.Error(), "nodeID", nodeID)
			return nil, fmt.Errorf("failed to get peer: %w", err)
		}
		return peerToIPMultiaddrs(peer, maddr)
	}
	// If we have a webmesh protocol, we can resolve the peer ID
	id, err := protocol.PeerIDFromWebmeshAddr(maddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get any webmesh protocol value: %w", err)
	}
	pubkey, err := id.ExtractPublicKey()
	if err != nil {
		t.log.Error("Failed to extract public key from id", "error", err.Error(), "id", string(id))
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}
	wgkey, ok := pubkey.(*wmcrypto.WebmeshPublicKey)
	if !ok {
		t.log.Error("Failed to cast public key to wireguard public key", "error", err.Error(), "id", string(id))
		return nil, fmt.Errorf("failed to cast public key to wireguard public key")
	}
	peer, err := t.node.Storage().MeshDB().Peers().GetByPubKey(ctx, wgkey)
	if err != nil {
		t.log.Error("Failed to lookup peer by their public key", "error", err.Error(), "id", id)
		return nil, fmt.Errorf("failed to get peer: %w", err)
	}
	return peerToIPMultiaddrs(peer, maddr)
}

// Protocol returns the set of protocols handled by this transport.
func (t *WebmeshTransport) Protocols() []int {
	return []int{protocol.P_WEBMESH}
}

// Proxy returns true if this is a proxy transport.
func (t *WebmeshTransport) Proxy() bool {
	return true
}

// Close closes the transport.
func (t *WebmeshTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.started.Load() {
		return nil
	}
	defer t.started.Store(false)
	ctx := context.Background()
	if t.opts.StopTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.opts.StopTimeout)
		defer cancel()
	}
	if t.svcs != nil {
		defer t.svcs.Shutdown(ctx)
	}
	err := t.node.Close(ctx)
	if err != nil {
		if errors.IsNoLeader(err) {
			// This error could possibly mean we were a single node cluster.
			// Silently ignore it.
			t.log.Debug("failed to close node", "error", err.Error())
			return nil
		}
		return fmt.Errorf("failed to close node: %w", err)
	}
	return nil
}

func (t *WebmeshTransport) startNode(ctx context.Context, laddr ma.Multiaddr) (meshnode.Node, error) {
	if t.opts.StartTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.opts.StartTimeout)
		defer cancel()
	}
	conf, err := t.opts.Config.Global.ApplyGlobals(t.opts.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to apply global config: %w", err)
	}
	t.conf = conf

	// Check if our listen address is trying to discover a mesh or announce one
	_, err = laddr.ValueForProtocol(protocol.P_WEBMESH)
	if err == nil {
		rendezvous, err := protocol.RendezvousFromWebmeshAddr(laddr)
		if err == nil {
			t.log.Debug("Starting webmesh node in discovery mode", "rendezvous", rendezvous)
			if conf.Bootstrap.Enabled || conf.Discovery.Announce {
				conf.Discovery.Announce = true
				conf.Discovery.Rendezvous = rendezvous
			} else {
				conf.Discovery.Discover = true
				conf.Discovery.Rendezvous = rendezvous
			}
		}
	}

	// Validate the config
	err = conf.Validate()
	if err != nil {
		return nil, fmt.Errorf("failed to validate config: %w", err)
	}

	// Build out everything we need for a new node
	meshConfig, err := conf.NewMeshConfig(ctx, t.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create mesh config: %w", err)
	}
	meshConfig.Key = t.key
	node := meshnode.NewWithLogger(logging.NewLogger(conf.Global.LogLevel, conf.Global.LogFormat).With("component", "webmesh-node"), meshConfig)
	storageProvider, err := conf.NewStorageProvider(ctx, node, conf.Bootstrap.Force)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage provider: %w", err)
	}
	connectOpts, err := conf.NewConnectOptions(ctx, node, storageProvider, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create connect options: %w", err)
	}

	// Define cleanup handlers
	var cleanFuncs []func() error
	handleErr := func(cause error) error {
		for _, clean := range cleanFuncs {
			if err := clean(); err != nil {
				t.log.Warn("failed to clean up", "error", err.Error())
			}
		}
		return cause
	}

	t.log.Info("Starting webmesh node")
	err = storageProvider.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start raft node: %w", err)
	}
	cleanFuncs = append(cleanFuncs, func() error {
		return storageProvider.Close()
	})
	err = node.Connect(ctx, connectOpts)
	if err != nil {
		return nil, handleErr(fmt.Errorf("failed to connect to mesh: %w", err))
	}
	cleanFuncs = append(cleanFuncs, func() error {
		return node.Close(ctx)
	})

	// Start any mesh services
	srvOpts, err := conf.Services.NewServiceOptions(ctx, node)
	if err != nil {
		return nil, handleErr(fmt.Errorf("failed to create service options: %w", err))
	}
	t.svcs, err = services.NewServer(ctx, srvOpts)
	if err != nil {
		return nil, handleErr(fmt.Errorf("failed to create mesh services: %w", err))
	}
	features := conf.Services.NewFeatureSet(storageProvider, conf.Services.API.ListenPort())
	if !conf.Services.API.Disabled {
		err = conf.Services.RegisterAPIs(ctx, node, t.svcs, features)
		if err != nil {
			return nil, handleErr(fmt.Errorf("failed to register APIs: %w", err))
		}
	}
	errs := make(chan error, 1)
	go func() {
		t.log.Info("Starting webmesh services")
		if err := t.svcs.ListenAndServe(); err != nil {
			errs <- fmt.Errorf("start mesh services %w", err)
		}
	}()

	// Wait for the node to be ready
	t.log.Info("Waiting for webmesh node to be ready")
	select {
	case <-node.Ready():
	case err := <-errs:
		return nil, handleErr(err)
	case <-ctx.Done():
		return nil, handleErr(fmt.Errorf("failed to start mesh node: %w", ctx.Err()))
	}

	// Subscribe to peer updates
	t.log.Debug("Subscribing to peer updates")
	_, err = node.Storage().MeshDB().Peers().Subscribe(context.Background(), func(peers []types.MeshNode) {
		for _, peer := range peers {
			err := t.registerNode(context.Background(), peer)
			if err != nil {
				t.log.Error("Failed to register node to peerstore", "error", err.Error())
			}
		}
	})
	if err != nil {
		return nil, handleErr(fmt.Errorf("failed to subscribe to peers: %w", err))
	}
	// Automatically add our direct peers
	t.log.Debug("Adding direct peers to peerstore")
	for _, wgpeer := range node.Network().WireGuard().Peers() {
		id, err := peer.IDFromPublicKey(wgpeer.PublicKey)
		if err != nil {
			return nil, handleErr(fmt.Errorf("failed to get peer ID from public key: %w", err))
		}
		t.log.Debug("Adding peer to peerstore", "peer", id, "multiaddrs", wgpeer.Multiaddrs)
		t.host.Peerstore().AddAddrs(id, wgpeer.Multiaddrs, peerstore.PermanentAddrTTL)
		err = t.host.Peerstore().AddPubKey(id, wgpeer.PublicKey)
		if err != nil {
			return nil, handleErr(fmt.Errorf("failed to add public key to peerstore: %w", err))
		}
	}
	t.log.Info("Webmesh node is ready")
	return node, nil
}

func (t *WebmeshTransport) registerMultiaddrsForListener(ctx context.Context, lis mnet.Listener) error {
	addrs, err := t.multiaddrsForLocalListenAddr(lis.Addr())
	if err != nil {
		return fmt.Errorf("failed to get multiaddrs for listener: %w", err)
	}
	t.laddrs = append(t.laddrs, addrs...)
	addrstrs := func() []string {
		var straddrs []string
		for _, addr := range t.laddrs {
			straddrs = append(straddrs, addr.String())
		}
		return straddrs
	}()
	if !t.node.Storage().Consensus().IsMember() {
		c, err := t.node.DialLeader(ctx)
		if err != nil {
			return fmt.Errorf("failed to dial leader: %w", err)
		}
		defer c.Close()
		_, err = v1.NewMembershipClient(c).Update(ctx, &v1.UpdateRequest{
			Id:         t.node.ID().String(),
			Multiaddrs: addrstrs,
		})
		if err != nil {
			return fmt.Errorf("failed to update membership: %w", err)
		}
		return nil
	}
	// We can write it directly to storage
	self, err := t.node.Storage().MeshDB().Peers().Get(ctx, t.node.ID())
	if err != nil {
		return fmt.Errorf("failed to get self: %w", err)
	}
	self.Multiaddrs = addrstrs
	err = t.node.Storage().MeshDB().Peers().Put(ctx, self)
	if err != nil {
		return fmt.Errorf("failed to update self: %w", err)
	}
	return nil
}

func (t *WebmeshTransport) multiaddrsForLocalListenAddr(listenAddr net.Addr) ([]ma.Multiaddr, error) {
	var lisaddr ma.Multiaddr
	var ip netip.Addr
	var err error
	switch v := listenAddr.(type) {
	case *net.TCPAddr:
		ip = v.AddrPort().Addr()
		lisaddr, err = ma.NewMultiaddr(fmt.Sprintf("/tcp/%d", v.Port))
	case *net.UDPAddr:
		ip = v.AddrPort().Addr()
		lisaddr, err = ma.NewMultiaddr(fmt.Sprintf("/udp/%d", v.Port))
	default:
		err = fmt.Errorf("unknown listener type: %T", listenAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create listener multiaddr: %w", err)
	}
	// Append the webmesh protocol ID and arguments to the listener address
	// secaddr := protocol.WithPeerID(t.key.ID())
	var addrs []ma.Multiaddr
	if ip.Is4() {
		ip4addr, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/%s", ip))
		if err != nil {
			return nil, fmt.Errorf("failed to create ip4 multiaddr: %w", err)
		}
		addrs = append(addrs, ma.Join(ip4addr, lisaddr))
		dnsaddr, err := ma.NewMultiaddr(fmt.Sprintf("/dns4/%s.%s", t.node.ID(), strings.TrimSuffix(t.node.Domain(), ".")))
		if err != nil {
			return nil, fmt.Errorf("failed to create domain multiaddr: %w", err)
		}
		addrs = append(addrs, ma.Join(dnsaddr, lisaddr))
	}
	if ip.Is6() {
		ip6addr, err := ma.NewMultiaddr(fmt.Sprintf("/ip6/%s", ip))
		if err != nil {
			return nil, fmt.Errorf("failed to create ip6 multiaddr: %w", err)
		}
		addrs = append(addrs, ma.Join(ip6addr, lisaddr))
		dnsaddr, err := ma.NewMultiaddr(fmt.Sprintf("/dns6/%s.%s", t.node.ID(), strings.TrimSuffix(t.node.Domain(), ".")))
		if err != nil {
			return nil, fmt.Errorf("failed to create domain multiaddr: %w", err)
		}
		addrs = append(addrs, ma.Join(dnsaddr, lisaddr))
	}
	return addrs, nil
}

func (t *WebmeshTransport) registerNode(ctx context.Context, node types.MeshNode) error {
	ps := t.host.Peerstore()
	pubkey, err := wmcrypto.DecodePublicKey(node.GetPublicKey())
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}
	id, err := peer.IDFromPublicKey(pubkey)
	if err != nil {
		return fmt.Errorf("failed to get peer ID from public key: %w", err)
	}
	for _, addr := range node.GetMultiaddrs() {
		a, err := ma.NewMultiaddr(addr)
		if err != nil {
			t.log.Error("Failed to parse multiaddr", "error", err.Error(), "multiaddr", addr)
			continue
		}
		ps.AddAddr(id, a, peerstore.PermanentAddrTTL)
	}
	err = t.host.Peerstore().AddPubKey(id, pubkey)
	if err != nil {
		return fmt.Errorf("failed to add public key to peerstore: %w", err)
	}
	return nil
}

func peerToIPMultiaddrs(peer types.MeshNode, maddr ma.Multiaddr) ([]ma.Multiaddr, error) {
	var peerv4addr, peerv6addr netip.Prefix
	var err error
	if peer.PrivateIPv4 != "" {
		peerv4addr, err = netip.ParsePrefix(peer.PrivateIPv4)
		if err != nil {
			return nil, fmt.Errorf("failed to parse peer address: %w", err)
		}
	}
	if peer.PrivateIPv6 != "" {
		peerv6addr, err = netip.ParsePrefix(peer.PrivateIPv6)
		if err != nil {
			return nil, fmt.Errorf("failed to parse peer address: %w", err)
		}
	}
	port, err := maddr.ValueForProtocol(ma.P_TCP)
	if err != nil {
		return nil, fmt.Errorf("failed to get port from multiaddr: %w", err)
	}
	var addrs []ma.Multiaddr
	if peerv4addr.IsValid() {
		addr, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%s", peerv4addr.Addr(), port))
		if err != nil {
			return nil, fmt.Errorf("failed to create multiaddr: %w", err)
		}
		addrs = append(addrs, addr)
	}
	if peerv6addr.IsValid() {
		addr, err := ma.NewMultiaddr(fmt.Sprintf("/ip6/%s/tcp/%s", peerv6addr.Addr(), port))
		if err != nil {
			return nil, fmt.Errorf("failed to create multiaddr: %w", err)
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}
