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

// Package wgtransport implements a Webmesh WireGuard transport for libp2p.
package wgtransport

import (
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/netip"
	"runtime"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/pnet"
	"github.com/libp2p/go-libp2p/core/transport"
	ma "github.com/multiformats/go-multiaddr"
	mnet "github.com/multiformats/go-multiaddr/net"

	"github.com/webmeshproj/webmesh/pkg/context"
	wmcrypto "github.com/webmeshproj/webmesh/pkg/crypto"
	wmproto "github.com/webmeshproj/webmesh/pkg/libp2p/protocol"
	p2putil "github.com/webmeshproj/webmesh/pkg/libp2p/util"
	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/meshnet/endpoints"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system"
	netutil "github.com/webmeshproj/webmesh/pkg/meshnet/util"
	"github.com/webmeshproj/webmesh/pkg/meshnet/wireguard"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// WireGuardTransport is the webmesh wireguard transport. This transport does not run a
// full mesh node, but rather utilizes libp2p streams to perform an authenticated
// keypair negotiation to compute IPv6 addresses for peers.
type WireGuardTransport interface {
	// Closer for the underlying transport that shuts down the webmesh node.
	io.Closer
	// Transport is the underlying libp2p Transport.
	transport.Transport
	// Resolver is a resolver that uses knowledge of local peers to resolve addresses.
	// transport.Resolver
}

// Constructor is the constructor for the webmesh transport.
type Constructor func(tu transport.Upgrader, host host.Host, key crypto.PrivKey, psk pnet.PSK, gater connmgr.ConnectionGater, rcmgr network.ResourceManager) (WireGuardTransport, error)

// Transport is the webmesh wireguard transport.
type Transport struct {
	peerID peer.ID
	host   host.Host
	psk    pnet.PSK
	key    wmcrypto.PrivateKey
	p2ptu  transport.Upgrader
	rcmgr  network.ResourceManager
	gater  connmgr.ConnectionGater
	iface  wireguard.Interface
	eps    endpoints.PrefixList
	log    *slog.Logger
}

// NewOptions returns a chained option for all the components of a webmesh transport.
func NewOptions(log *slog.Logger) libp2p.Option {
	return libp2p.ChainOptions(
		libp2p.Transport(NewWithLogger(log)),
		libp2p.Security(wmproto.SecurityID, NewSecurity),
		libp2p.AddrsFactory(func(addrs []ma.Multiaddr) []ma.Multiaddr {
			var out []ma.Multiaddr
			for _, addr := range addrs {
				out = append(out, wmproto.Decapsulate(addr))
			}
			return out
		}),
		libp2p.DefaultListenAddrs,
		libp2p.DefaultSecurity,
		libp2p.DefaultMuxers,
	)
}

// NewWithLogger returns a new constructor for a webmesh transport using the given logger.
func NewWithLogger(log *slog.Logger) Constructor {
	if log == nil {
		log = logging.NewLogger("")
	}
	return func(tu transport.Upgrader, host host.Host, key crypto.PrivKey, psk pnet.PSK, gater connmgr.ConnectionGater, rcmgr network.ResourceManager) (WireGuardTransport, error) {
		return newWebmeshTransport(log, tu, host, key, psk, gater, rcmgr)
	}
}

// New is the standard constructor for a webmesh transport.
func New(tu transport.Upgrader, host host.Host, key crypto.PrivKey, psk pnet.PSK, gater connmgr.ConnectionGater, rcmgr network.ResourceManager) (WireGuardTransport, error) {
	return NewWithLogger(logging.NewLogger(""))(tu, host, key, psk, gater, rcmgr)
}

// newWebmeshTransport is the constructor for the webmesh transport.
func newWebmeshTransport(log *slog.Logger, tu transport.Upgrader, host host.Host, key crypto.PrivKey, psk pnet.PSK, gater connmgr.ConnectionGater, rcmgr network.ResourceManager) (WireGuardTransport, error) {
	var rt Transport
	var err error
	rt.log = log
	rt.host = host
	rt.psk = psk
	rt.rcmgr = rcmgr
	rt.gater = gater
	rt.p2ptu = tu
	rt.key, err = p2putil.ToWebmeshPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key to webmesh identity: %w", err)
	}
	rt.peerID, err = peer.IDFromPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to extract peer ID from private key: %w", err)
	}
	ctx := context.WithLogger(context.Background(), rt.log)

	// Detect our public endpoints (libp2p probably has mechanisms for this already)
	rt.eps, err = endpoints.Detect(ctx, endpoints.DetectOpts{
		DetectPrivate: true,
		DetectIPv6:    true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to detect local endpoints: %w", err)
	}

	// Determine what our local network will be.
	var ula netip.Prefix
	var addr netip.Addr
	if len(psk) > 0 {
		// We are going to seed the ULA with the PSK and use it for all connections.
		ula = netutil.GenerateULAWithSeed(psk)
		addr = netutil.AssignToPrefix(ula, rt.key.PublicKey()).Addr()
	} else {
		// We'll generate our own unique local addresses.
		ula, addr = netutil.GenerateULAWithKey(rt.key.PublicKey())
	}
	rt.log.Debug("Calculated our local IPv6 address space", "ula", ula.String())
	// We go ahead and create an interface for ourself. If we can't do this we'll fail to
	// do pretty much everything.
	wgopts := wireguard.Options{
		NodeID: types.NodeID(host.ID().String()),
		// Will only work on Linux/Windows, needs to be utun+ on macOS.
		Name: func() string {
			if runtime.GOOS == "darwin" {
				return "utun9"
			}
			// Pick a random number to append to the interface name
			r := rand.New(rand.NewSource(time.Now().UnixNano()))
			return fmt.Sprintf("webmesh%d", r.Intn(1000))
		}(),
		ForceName:   true,
		MTU:         system.DefaultMTU,
		NetworkV6:   ula,
		AddressV6:   netip.PrefixFrom(addr, wmproto.PrefixSize),
		DisableIPv4: true,
	}
	rt.log.Debug("Configuring wireguard interface", "options", wgopts)
	iface, err := wireguard.New(ctx, &wgopts)
	if err != nil {
		return nil, fmt.Errorf("failed to create wireguard interface: %w", err)
	}
	err = iface.AddRoute(ctx, ula)
	if err != nil && !system.IsRouteExists(err) {
		return nil, fmt.Errorf("failed to add route: %w", err)
	}
	err = iface.Configure(ctx, rt.key)
	if err != nil {
		return nil, fmt.Errorf("failed to configure wireguard interface: %w", err)
	}
	rt.iface = iface
	return &rt, nil
}

// CanDial returns true if this transport knows how to dial the given
// multiaddr.
//
// Returning true does not guarantee that dialing this multiaddr will
// succeed. This function should *only* be used to preemptively filter
// out addresses that we can't dial.
func (t *Transport) CanDial(addr ma.Multiaddr) bool {
	return wmproto.IsWebmeshCapableAddr(addr)
}

// Dial dials the given multiaddr.
func (t *Transport) Dial(ctx context.Context, rmaddr ma.Multiaddr, p peer.ID) (transport.CapableConn, error) {
	var dialer mnet.Dialer
	log := t.log.With("peer", p.String(), "raddr", rmaddr.String())
	ctx = context.WithLogger(ctx, log)
	direction := network.DirOutbound
	if ok, isClient, _ := network.GetSimultaneousConnect(ctx); ok && !isClient {
		direction = network.DirInbound
	}
	connScope, err := t.rcmgr.OpenConnection(direction, false, rmaddr)
	if err != nil {
		log.Error("Failed to open connection", "error", err.Error())
		return nil, fmt.Errorf("failed to open connection: %w", err)
	}
	defer connScope.Done()
	conn, err := dialer.DialContext(ctx, wmproto.Decapsulate(rmaddr))
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	return t.p2ptu.Upgrade(ctx, t, t.WrapConn(conn), direction, p, connScope)
}

// Listen listens on the passed multiaddr.
func (t *Transport) Listen(laddr ma.Multiaddr) (transport.Listener, error) {
	t.log.Debug("Setting up webmesh listener", "laddr", laddr.String())
	lis, err := mnet.Listen(wmproto.Decapsulate(laddr))
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}
	return t.p2ptu.UpgradeListener(t, t.WrapListener(lis)), nil
}

// Protocol returns the set of protocols handled by this transport.
func (t *Transport) Protocols() []int {
	return []int{
		wmproto.P_WEBMESH,
		ma.P_TCP,
	}
}

// Proxy returns true if this is a proxy transport.
func (t *Transport) Proxy() bool {
	return false
}

// Close shuts down the wireguard interface.
func (t *Transport) Close() error {
	ctx := context.WithLogger(context.Background(), t.log)
	if t.iface != nil {
		t.log.Debug("Shutting down wireguard interface")
		return t.iface.Close(ctx)
	}
	return nil
}

// WireGuardEndpoints returns the exposed endpoints for our wireguard interface.
func (t *Transport) WireGuardEndpoints() []string {
	var out []string
	wgport, _ := t.iface.ListenPort()
	addrports := t.eps.AddrPorts(uint16(wgport))
	for _, ap := range addrports {
		out = append(out, ap.String())
	}
	return out
}

func (t *Transport) WrapConn(c mnet.Conn) *Conn {
	return &Conn{
		Conn:   c,
		rt:     t,
		lkey:   t.key,
		lpeer:  t.peerID,
		rmaddr: wmproto.Encapsulate(c.RemoteMultiaddr(), "CG="),
		iface:  t.iface,
		eps:    t.WireGuardEndpoints(),
		log: t.log.With(
			"local-peer", t.host.ID().String(),
			"local-multiaddr", c.LocalMultiaddr().String(),
			"remote-multiaddr", c.RemoteMultiaddr().String(),
		),
	}
}

func (t *Transport) WrapListener(l mnet.Listener) *Listener {
	ln := &Listener{
		Listener: l,
		rt:       t,
		conns:    make(chan *Conn, 10),
		donec:    make(chan struct{}),
	}
	go ln.handleIncoming()
	return ln
}
