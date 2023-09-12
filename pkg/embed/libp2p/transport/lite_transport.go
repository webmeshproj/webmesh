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

package transport

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/pnet"
	"github.com/libp2p/go-libp2p/core/sec"
	"github.com/libp2p/go-libp2p/core/transport"
	basichost "github.com/libp2p/go-libp2p/p2p/host/basic"
	"github.com/libp2p/go-libp2p/p2p/transport/quicreuse"
	ma "github.com/multiformats/go-multiaddr"
	mnet "github.com/multiformats/go-multiaddr/net"

	"github.com/webmeshproj/webmesh/pkg/context"
	wmcrypto "github.com/webmeshproj/webmesh/pkg/crypto"
	wmproto "github.com/webmeshproj/webmesh/pkg/embed/libp2p/protocol"
	"github.com/webmeshproj/webmesh/pkg/embed/libp2p/security"
	p2putil "github.com/webmeshproj/webmesh/pkg/embed/libp2p/util"
	"github.com/webmeshproj/webmesh/pkg/net/endpoints"
	"github.com/webmeshproj/webmesh/pkg/net/system"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
	"github.com/webmeshproj/webmesh/pkg/util/logutil"
	"github.com/webmeshproj/webmesh/pkg/util/netutil"
)

// Make sure we implement the interface.
var _ LiteTransport = (*LiteWebmeshTransport)(nil)

// PrefixSize is the local prefix size assigned to each peer.
const PrefixSize = 112

// LiteTransport is the lite webmesh transport. This transport does not run a
// full mesh node, but rather utilizes libp2p streams to perform an authenticated
// keypair negotiation to compute IPv6 addresses for peers.
type LiteTransport interface {
	// Closer for the underlying transport that shuts down the webmesh node.
	io.Closer
	// Transport is the underlying libp2p Transport.
	transport.Transport
	// Resolver is a resolver that uses knowledge of local peers to resolve addresses.
	transport.Resolver
}

// LiteOptions are the options for the lite webmesh transport.
type LiteOptions struct {
	// Config is the configuration for the WireGuard interface.
	Config WireGuardOptions
	// EndpointDetection are options for doing public endpoint
	// detection for the wireguard interface.
	EndpointDetection *endpoints.DetectOpts
	// Logger is the logger to use for the webmesh transport.
	// If nil, an empty logger will be used.
	Logger *slog.Logger
}

// WireGuardOptions are options for configuring the WireGuard interface on
// the transport.
type WireGuardOptions struct {
	// ListenPort is the port to listen on.
	// If 0, a default port of 51820 will be used.
	ListenPort uint16
	// InterfaceName is the name of the interface to use.
	// If empty, a default platform dependent name will be used.
	InterfaceName string
	// ForceInterfaceName forces the interface name to be used.
	// If false, the interface name will be changed if it already exists.
	ForceInterfaceName bool
	// MTU is the MTU to use for the interface.
	// If 0, a default MTU of 1420 will be used.
	MTU int
}

func (w *WireGuardOptions) Default() {
	if w.ListenPort == 0 {
		w.ListenPort = wireguard.DefaultListenPort
	}
	if w.InterfaceName == "" {
		w.InterfaceName = wireguard.DefaultInterfaceName
	}
	if w.MTU == 0 {
		w.MTU = system.DefaultMTU
	}
}

// LiteTransportBuilder is the signature of a function that builds a webmesh lite transport.
type LiteTransportBuilder func(tu transport.Upgrader, host host.Host, key crypto.PrivKey, psk pnet.PSK, connManager *quicreuse.ConnManager, gater connmgr.ConnectionGater, rcmgr network.ResourceManager) (Transport, error)

// SecurityTransportBuilder is the signature of a function that builds a webmesh secure transport.
type SecurityTransportBuilder func() sec.SecureTransport

// New returns a new lite webmesh transport builder.
func NewLite(opts LiteOptions) (LiteTransportBuilder, SecurityTransportBuilder, basichost.AddrsFactory) {
	opts.Config.Default()
	if opts.Logger == nil {
		opts.Logger = logutil.NewLogger("")
	}
	rt := &LiteWebmeshTransport{
		opts: opts,
		conf: opts.Config,
		log:  opts.Logger.With("component", "webmesh-lite-transport"),
	}
	var secTransport security.SecureTransport
	transportConstructor := func(tu transport.Upgrader, host host.Host, privkey crypto.PrivKey, psk pnet.PSK, connManager *quicreuse.ConnManager, gater connmgr.ConnectionGater, rcmgr network.ResourceManager) (Transport, error) {
		if len(psk) > 0 {
			rt.log.Error("Webmesh doesn't support private networks yet.")
			// But we definitely could in the future.
			return nil, fmt.Errorf("webmesh doesn't support private networks yet")
		}
		ctx := context.WithLogger(context.Background(), rt.log)
		key, err := p2putil.ToWebmeshPrivateKey(privkey)
		if err != nil {
			return nil, err
		}
		secTransport.SetKey(key)

		// Check if we are detecting public endpoints that we'll exchange with peers.
		if rt.opts.EndpointDetection != nil {
			eps, err := endpoints.Detect(ctx, *rt.opts.EndpointDetection)
			if err != nil {
				return nil, fmt.Errorf("failed to detect public endpoints: %w", err)
			}
			addrports := eps.AddrPorts(rt.opts.Config.ListenPort)
			for _, addrport := range addrports {
				rt.eps = append(rt.eps, addrport.String())
			}
		}
		secTransport.SetEndpoints(rt.eps)

		rt.key = key
		rt.host = host
		rt.tu = tu
		rt.rcmgr = rcmgr
		rt.connmgr = connManager
		rt.gater = gater

		err = rt.host.Peerstore().AddProtocols(rt.host.ID(), wmproto.SecurityID)
		if err != nil {
			return nil, fmt.Errorf("failed to add protocols to peerstore: %w", err)
		}

		// We set our local network to be a ULA network derived from our public key.
		// This is a /32 network (roughly the number of IPv4 addresses in the world).
		// We then assign /112 networks to each incoming peer according to their public
		// key. These addresses can be used for relaying to other peers in their network.
		// But this is not supported yet. For now we only support direct connections by
		// negotiating what our allowed IP addresses should be on both sides.
		rt.lula, rt.laddr = netutil.GenerateULAWithKey(key.PublicKey())
		rt.log = rt.log.With("local-ula", rt.lula.String(), "local-addr", rt.laddr.String())
		rt.log.Info("Generated local ULA network, configuring WireGuard",
			"local-ula", rt.lula.String(), "local-addr", rt.laddr.String())
		wgopts := wireguard.Options{
			NodeID:      host.ID().String(),
			ListenPort:  int(rt.conf.ListenPort),
			Name:        rt.conf.InterfaceName,
			ForceName:   rt.conf.ForceInterfaceName,
			MTU:         rt.conf.MTU,
			NetworkV6:   rt.lula,
			AddressV6:   netip.PrefixFrom(rt.laddr, PrefixSize),
			DisableIPv4: true,
		}
		iface, err := wireguard.New(ctx, &wgopts)
		if err != nil {
			return nil, fmt.Errorf("failed to create wireguard interface: %w", err)
		}
		// Add a route for the entire ULA network to the interface.
		err = iface.AddRoute(ctx, rt.lula)
		if err != nil {
			defer func() { _ = iface.Close(ctx) }()
			return nil, fmt.Errorf("failed to add route for ULA network: %w", err)
		}
		rt.iface = iface
		secTransport.SetInterface(iface)

		rt.log.Debug("Webmesh transport initialized")
		return rt, nil
	}
	securityConstructor := func() sec.SecureTransport {
		return &secTransport
	}
	return transportConstructor, securityConstructor, rt.BroadcastAddrs
}

// LiteWebmeshTransport is the lite webmesh transport.
type LiteWebmeshTransport struct {
	opts    LiteOptions
	conf    WireGuardOptions
	host    host.Host
	key     wmcrypto.PrivateKey
	tu      transport.Upgrader
	rcmgr   network.ResourceManager
	connmgr *quicreuse.ConnManager
	gater   connmgr.ConnectionGater
	log     *slog.Logger
	iface   wireguard.Interface
	lula    netip.Prefix
	laddr   netip.Addr
	eps     []string
	mu      sync.Mutex
}

// Close shuts down the wireguard interface.
func (t *LiteWebmeshTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.iface == nil {
		return nil
	}
	return t.iface.Close(context.WithLogger(context.Background(), t.log))
}

// CanDial returns true if this transport knows how to dial the given
// multiaddr.
//
// Returning true does not guarantee that dialing this multiaddr will
// succeed. This function should *only* be used to preemptively filter
// out addresses that we can't dial.
func (t *LiteWebmeshTransport) CanDial(addr ma.Multiaddr) bool {
	return wmproto.IsWebmeshAddr(addr)
}

// Dial dials a remote peer. It should try to reuse local listener
// addresses if possible, but it may choose not to.
func (t *LiteWebmeshTransport) Dial(ctx context.Context, rmaddr ma.Multiaddr, p peer.ID) (transport.CapableConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	log := t.log.With("peer", p.String(), "insecure-multiaddr", rmaddr.String())
	log.Debug("Dialing remote peer")
	var dialer mnet.Dialer
	connScope, err := t.rcmgr.OpenConnection(network.DirOutbound, false, rmaddr)
	if err != nil {
		log.Debug("Failed to open connection", "error", err.Error())
		return nil, fmt.Errorf("failed to open connection: %w", err)
	}
	defer connScope.Done()
	c, err := dialer.DialContext(ctx, rmaddr)
	if err != nil {
		t.log.Debug("Failed to dial remote peer", "error", err.Error())
		return nil, fmt.Errorf("failed to dial remote peer: %w", err)
	}
	u, err := t.tu.Upgrade(ctx, t, c, network.DirOutbound, p, connScope)
	if err != nil {
		t.log.Debug("Failed to upgrade connection", "error", err.Error())
		return nil, fmt.Errorf("failed to upgrade connection: %w", err)
	}
	return u, nil
}

// Listen listens on the passed multiaddr.
func (t *LiteWebmeshTransport) Listen(laddr ma.Multiaddr) (transport.Listener, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// Append webmesh security to the address
	laddr = wmproto.ToWebmeshAddr(laddr)
	t.log.Debug("Listening for webmesh connections", "laddr", laddr.String())
	lis, err := mnet.Listen(laddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}
	return t.tu.UpgradeListener(t, lis), nil
}

// Resolve attempts to resolve the given multiaddr to a list of addresses.
func (t *LiteWebmeshTransport) Resolve(ctx context.Context, maddr ma.Multiaddr) ([]ma.Multiaddr, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return nil, fmt.Errorf("not implemented")
}

// BroadcastAddrs implements AddrsFactory on top of this transport. It automatically appends
// our webmesh ID and any DNS addresses we have to the list of addresses.
func (t *LiteWebmeshTransport) BroadcastAddrs(addrs []ma.Multiaddr) []ma.Multiaddr {
	var out []ma.Multiaddr
	for _, addr := range addrs {
		if wmproto.IsWebmeshCapableAddr(addr) {
			// Add webmesh security
			addr = wmproto.ToWebmeshAddr(addr)
		}
		out = append(out, addr)
	}
	return out
}

// Protocol returns the set of protocols handled by this transport.
func (t *LiteWebmeshTransport) Protocols() []int {
	return []int{wmproto.P_WEBMESH}
}

// Proxy returns true if this is a proxy transport.
func (t *LiteWebmeshTransport) Proxy() bool {
	return true
}
