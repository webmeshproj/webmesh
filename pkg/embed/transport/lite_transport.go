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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/libp2p/go-libp2p/core/connmgr"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/pnet"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/sec"
	"github.com/libp2p/go-libp2p/core/transport"
	basichost "github.com/libp2p/go-libp2p/p2p/host/basic"
	"github.com/libp2p/go-libp2p/p2p/transport/quicreuse"
	ma "github.com/multiformats/go-multiaddr"
	mnet "github.com/multiformats/go-multiaddr/net"

	"github.com/webmeshproj/webmesh/pkg/context"
	wmcrypto "github.com/webmeshproj/webmesh/pkg/crypto"
	wmproto "github.com/webmeshproj/webmesh/pkg/embed/protocol"
	"github.com/webmeshproj/webmesh/pkg/net/endpoints"
	"github.com/webmeshproj/webmesh/pkg/net/system"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
	"github.com/webmeshproj/webmesh/pkg/util/logutil"
	"github.com/webmeshproj/webmesh/pkg/util/netutil"
)

// Make sure we implement the interface.
var _ LiteTransport = (*LiteWebmeshTransport)(nil)
var _ sec.SecureTransport = (*LiteSecureTransport)(nil)
var _ sec.SecureConn = (*LiteSecureConn)(nil)

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
	var secTransport LiteSecureTransport
	secTransport.log = opts.Logger.With("component", "webmesh-lite-secure-transport")

	transportConstructor := func(tu transport.Upgrader, host host.Host, privkey crypto.PrivKey, psk pnet.PSK, connManager *quicreuse.ConnManager, gater connmgr.ConnectionGater, rcmgr network.ResourceManager) (Transport, error) {
		if len(psk) > 0 {
			rt.log.Error("Webmesh doesn't support private networks yet.")
			// But we definitely could in the future.
			return nil, fmt.Errorf("webmesh doesn't support private networks yet")
		}
		ctx := context.WithLogger(context.Background(), rt.log)
		key, err := toWebmeshPrivateKey(privkey)
		if err != nil {
			return nil, err
		}
		// Check if we are detecting public endpoints that we'll exchange with peers.
		if rt.opts.EndpointDetection != nil {
			eps, err := endpoints.Detect(ctx, *rt.opts.EndpointDetection)
			if err != nil {
				return nil, fmt.Errorf("failed to detect public endpoints: %w", err)
			}
			addrports := eps.AddrPorts(rt.opts.Config.ListenPort)
			for _, addrport := range addrports {
				rt.eps = append(rt.eps, addrport.String())
				secTransport.eps = append(rt.eps, addrport.String())
			}
		}
		rt.key = key
		rt.host = host
		secTransport.key = key
		secTransport.host = host
		rt.tu = tu
		rt.rcmgr = rcmgr
		rt.connmgr = connManager
		rt.gater = gater

		err = rt.host.Peerstore().AddProtocols(rt.host.ID(), wmproto.SecurityID)
		if err != nil {
			return nil, fmt.Errorf("failed to add protocols to peerstore: %w", err)
		}
		err = rt.host.Peerstore().AddPrivKey(rt.host.ID(), privkey)
		if err != nil {
			return nil, fmt.Errorf("failed to add private key to peerstore: %w", err)
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
			NodeID:      host.ID().ShortString(),
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
		secTransport.iface = iface
		rt.host.SetStreamHandler(wmproto.SecurityID, func(s network.Stream) {
			err := handleEndpointNegotiation(context.WithLogger(context.Background(), secTransport.log), s, rt.iface, rt.key, rt.eps)
			if err != nil {
				rt.log.Error("Failed to handle endpoint negotiation", "error", err.Error())
				_ = s.Reset()
				return
			}
		})
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
	// For now we say we can dial any webmesh address.
	return wmproto.IsWebmeshCapableAddr(addr)
}

// Dial dials a remote peer. It should try to reuse local listener
// addresses if possible, but it may choose not to.
func (t *LiteWebmeshTransport) Dial(ctx context.Context, rmaddr ma.Multiaddr, p peer.ID) (transport.CapableConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	log := t.log.With("peer", p.ShortString(), "insecure-multiaddr", rmaddr.String())
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
	if !wmproto.IsWebmeshCapableAddr(laddr) {
		return nil, fmt.Errorf("multiaddr is not webmesh capable")
	}
	// Append webmesh security to the address
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
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []ma.Multiaddr
	for _, addr := range addrs {
		if wmproto.IsWebmeshCapableAddr(addr) {
			// Add webmesh security
			addr = wmproto.ToWebmeshAddr(addr)
		}
		out = append(out, addr)
	}
	t.host.Peerstore().SetAddrs(t.host.ID(), addrs, peerstore.PermanentAddrTTL)
	return out
}

// Protocol returns the set of protocols handled by this transport.
func (t *LiteWebmeshTransport) Protocols() []int {
	return []int{wmproto.Code}
}

// Proxy returns true if this is a proxy transport.
func (t *LiteWebmeshTransport) Proxy() bool {
	return true
}

// LiteSecureTransport provides a sec.SecureTransport that will automatically set up
// routes and compute addresses for peers as connections are opened.
type LiteSecureTransport struct {
	host  host.Host
	key   wmcrypto.PrivateKey
	iface wireguard.Interface
	eps   []string
	log   *slog.Logger
	mu    sync.Mutex
}

// SecureInbound secures an inbound connection.
// If p is empty, connections from any peer are accepted.
func (l *LiteSecureTransport) SecureInbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.iface == nil {
		l.log.Error("SecureInbound called before WireGuard interface was set")
		return nil, fmt.Errorf("wireguard interface is not set")
	}
	log := l.log.With("remote-peer", p.ShortString())
	log.Info("Securing inbound connection", "remote-peer", p.ShortString())
	// If the peer ID is empty, we don't know who this is, so we can't do anything
	// substantial for now.
	if p == "" {
		l.log.Debug("SecureInbound called with empty peer ID")
		return &LiteSecureConn{
			Conn:      insecure,
			lpeer:     l.host.ID(),
			rpeer:     p,
			rkey:      nil,
			transport: getTransport(insecure),
		}, nil
	}
	// Extract the public key from the peer ID.
	log.Debug("Extracting public key from peer ID")
	wmkey, err := extractWebmeshPublicKey(ctx, p)
	if err != nil {
		log.Error("Failed to convert public key to webmesh key", "error", err.Error())
		return nil, fmt.Errorf("failed to convert public key to webmesh key: %w", err)
	}
	// Configure wireguard for the peer.
	rula, raddr := netutil.GenerateULAWithKey(wmkey)
	err = l.iface.PutPeer(context.WithLogger(ctx, log), &wireguard.Peer{
		ID:         p.ShortString(),
		PublicKey:  wmkey,
		Multiaddrs: l.host.Peerstore().Addrs(p),
		// We expect the peer to invoke the stream handler for endpoint negotiation.
		Endpoint:    netip.AddrPort{},
		PrivateIPv6: netip.PrefixFrom(raddr, PrefixSize),
		AllowedIPs:  []netip.Prefix{rula},
	})
	if err != nil {
		l.log.Error("Failed to add peer to wireguard interface", "error", err.Error())
		return nil, fmt.Errorf("failed to add peer to wireguard interface: %w", err)
	}
	log.Info("Added peer to wireguard interface, waiting for endpoint negotiation")
	return &LiteSecureConn{
		Conn:      insecure,
		lpeer:     l.host.ID(),
		rpeer:     p,
		rkey:      wmkey,
		transport: getTransport(insecure),
	}, nil
}

// SecureOutbound secures an outbound connection.
func (l *LiteSecureTransport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.iface == nil {
		l.log.Error("SecureOutbound called before WireGuard interface was set")
		return nil, fmt.Errorf("wireguard interface is not set")
	}
	// Extract the peers public key from the peer ID.
	log := l.log.With("remote-peer", p.ShortString())
	log.Info("Securing outbound connection")
	wmkey, err := extractWebmeshPublicKey(ctx, p)
	if err != nil {
		log.Error("Failed to convert public key to webmesh key", "error", err.Error())
		return nil, fmt.Errorf("failed to convert public key to webmesh key: %w", err)
	}
	rula, raddr := netutil.GenerateULAWithKey(wmkey)
	// With most of the small things that can go wrong out of the way, try to get wireguard
	// ready for the connection. For now, we just add the peer's ULA and public key. PutPeer
	// current handles setting system routes as well.
	log.Debug("Adding peer to wireguard interface")
	err = l.iface.PutPeer(context.WithLogger(ctx, log), &wireguard.Peer{
		ID:          p.ShortString(),
		PublicKey:   wmkey,
		Endpoint:    netip.AddrPort{},
		PrivateIPv6: netip.PrefixFrom(raddr, PrefixSize),
		AllowedIPs:  []netip.Prefix{rula},
	})
	if err != nil {
		log.Error("Failed to add peer to wireguard interface", "error", err.Error())
		return nil, fmt.Errorf("failed to add peer to wireguard interface: %w", err)
	}
	// We now need to try to negotiate endpoints with the remote peer via another
	// transport.
	log.Debug("Attempting endpoint negotiation")
	conn, err := l.host.NewStream(ctx, p, wmproto.SecurityID)
	if err != nil {
		log.Error("Failed to dial remote peer for endpoint negotiation", "error", err.Error())
		return nil, fmt.Errorf("failed to dial remote peer for endpoint negotiation: %w", err)
	}
	err = handleEndpointNegotiation(ctx, conn, l.iface, l.key, l.eps)
	if err != nil {
		log.Error("Failed to handle endpoint negotiation", "error", err.Error())
		return nil, fmt.Errorf("failed to handle endpoint negotiation: %w", err)
	}
	return &LiteSecureConn{
		Conn:      insecure,
		lpeer:     l.host.ID(),
		rpeer:     p,
		rkey:      wmkey,
		transport: getTransport(insecure),
	}, nil
}

// ID is the protocol ID of the security protocol.
func (l *LiteSecureTransport) ID() protocol.ID { return wmproto.SecurityID }

// LiteSecureConn is a simple wrapper around a sec.SecureConn that just holds the
// peer information.
type LiteSecureConn struct {
	net.Conn
	lpeer     peer.ID
	rpeer     peer.ID
	rkey      crypto.PubKey
	transport string
}

// LocalPeer returns our peer ID
func (l *LiteSecureConn) LocalPeer() peer.ID { return l.lpeer }

// RemotePeer returns the peer ID of the remote peer.
func (l *LiteSecureConn) RemotePeer() peer.ID { return l.rpeer }

// RemotePublicKey returns the public key of the remote peer.
func (l *LiteSecureConn) RemotePublicKey() crypto.PubKey { return l.rkey }

// ConnState returns information about the connection state.
func (l *LiteSecureConn) ConnState() network.ConnectionState {
	return network.ConnectionState{
		Security:                  wmproto.SecurityID,
		Transport:                 l.transport,
		UsedEarlyMuxerNegotiation: true,
	}
}

func handleEndpointNegotiation(ctx context.Context, stream network.Stream, iface wireguard.Interface, key wmcrypto.PrivateKey, endpoints []string) error {
	defer func() { _ = stream.Reset() }()
	log := context.LoggerFrom(ctx)
	log.Info("Received inbound webmesh connection, negotiating endpoints")
	rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))
	// Make sure the peer has already been put in wireguard
	peer, ok := iface.Peers()[stream.Conn().RemotePeer().ShortString()]
	if !ok {
		log.Error("Peer not found in wireguard interface")
		return fmt.Errorf("peer not found in wireguard interface")
	}
	// We write a comma separated list of our endpoints (if any) to the stream.
	// We then follow it with a null byte and then a signature of the endpoints,
	// finally followed by a newline.
	// The remote peer will then do the same.
	var payload []byte
	if len(endpoints) > 0 {
		data := []byte(strings.Join(endpoints, ","))
		sig, err := key.Sign(data)
		if err != nil {
			log.Error("Failed to sign endpoints", "err", err)
			return fmt.Errorf("failed to sign endpoints: %w", err)
		}
		payload = []byte(fmt.Sprintf("%s\x00%s\n", data, string(sig)))
	} else {
		// Just the null byte
		payload = []byte("\x00")
	}
	_, err := rw.Write(payload)
	if err != nil {
		log.Error("Failed to write endpoints", "err", err)
		return fmt.Errorf("failed to write endpoints: %w", err)
	}
	// Flush the payload in a goroutine so we can read the response.
	go func() {
		if err := rw.Flush(); err != nil {
			log.Error("Failed to flush endpoints", "err", err)
			return
		}
	}()
	// We expected the same from the remote side.
	// We read the payload and verify the signature.
	// If the signature is valid, we add the endpoints to the peer.
	data, err := rw.ReadBytes('\n')
	if err != nil {
		log.Error("Failed to read endpoints", "err", err)
		return fmt.Errorf("failed to read endpoints: %w", err)
	}
	// Split the data into the endpoints and the signature.
	parts := bytes.Split(data, []byte("\x00"))
	if len(parts) != 2 {
		log.Error("Invalid endpoints payload")
		return fmt.Errorf("invalid endpoints payload")
	}
	eps, sig := bytes.TrimSpace(parts[0]), bytes.TrimSpace(parts[1])
	// If endpoints and signature are empty we are done.
	if len(eps) == 0 && len(sig) == 0 {
		log.Debug("No endpoints to add")
		return nil
	}
	// Verify the signature.
	ok, err = peer.PublicKey.Verify([]byte(eps), []byte(sig))
	if err != nil {
		log.Error("Failed to verify endpoints signature", "err", err)
		return fmt.Errorf("failed to verify endpoints signature: %w", err)
	}
	if !ok {
		log.Error("Invalid endpoints signature")
		return fmt.Errorf("invalid endpoints signature")
	}
	// Parse the endpoints.
	epStrings := strings.Split(string(eps), ",")
	if len(epStrings) == 0 {
		// Nothing to do
		return nil
	}
	// Pick the first one in the list for now. But negotiation
	// should continue until a connection can be established.
	epString := epStrings[0]
	addrport, err := netip.ParseAddrPort(epString)
	if err != nil {
		log.Error("Failed to parse endpoint", "endpoint", epString, "err", err)
		return fmt.Errorf("failed to parse endpoint %s: %w", epString, err)
	}
	peer.Endpoint = addrport
	err = iface.PutPeer(ctx, &peer)
	if err != nil {
		log.Error("Failed to update peer in wireguard interface", "err", err)
		return fmt.Errorf("failed to add peer to wireguard interface: %w", err)
	}
	return nil
}
