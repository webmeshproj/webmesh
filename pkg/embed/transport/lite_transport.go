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
	"sync/atomic"

	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/transport"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/config"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/embed/protocol"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
	"github.com/webmeshproj/webmesh/pkg/util/logutil"
)

// LiteTransport is the lite webmesh transport. This transport does not run
// a full mesh node, but rather utilizes libp2p streams to perform a secret
// key negotiation to compute IPv6 addresses for peers.
type LiteTransport interface {
	// Closer for the underlying transport that shuts down the webmesh node.
	io.Closer
	// Transport is the underlying libp2p Transport.
	transport.Transport
	// Resolver is a resolver that uses the mesh storage to lookup peers.
	transport.Resolver
}

// LiteOptions are the options for the lite webmesh transport.
type LiteOptions struct {
	// Config is the configuration for the WireGuard interface.
	Config config.WireGuardOptions
	// LogLevel is the log level for the webmesh transport.
	LogLevel string
	// Logger is the logger to use for the webmesh transport.
	// If nil, an empty logger will be used.
	Logger *slog.Logger
}

// New returns a new lite webmesh transport builder.
func NewLite(opts LiteOptions) (TransportBuilder, *LiteWebmeshTransport) {
	if opts.Logger == nil {
		opts.Logger = logutil.NewLogger("")
	}
	rt := &LiteWebmeshTransport{
		opts: opts,
		conf: opts.Config,
		log:  opts.Logger.With("component", "webmesh-lite-transport"),
	}
	return func(tu transport.Upgrader, host host.Host, rcmgr network.ResourceManager, privKey pcrypto.PrivKey) (Transport, error) {
		var raw []byte
		privkey, ok := privKey.(*pcrypto.Ed25519PrivateKey)
		if !ok {
			// Check if its already a webmesh key
			wmkey, ok := privKey.(crypto.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("%w: invalid private key type: %T", ErrInvalidSecureTransport, privKey)
			}
			raw, _ = wmkey.Raw()
		} else {
			raw, _ = privkey.Raw()
		}
		// Pack the key into a webmesh key
		key, err := crypto.PrivateKeyFromBytes(raw)
		if err != nil {
			return nil, fmt.Errorf("failed to create webmesh private key: %w", err)
		}
		rt.key = key
		rt.host = host
		rt.tu = tu
		rt.rcmgr = rcmgr
		return rt, nil
	}, rt
}

// LiteWebmeshTransport is the lite webmesh transport.
type LiteWebmeshTransport struct {
	started atomic.Bool
	opts    LiteOptions
	conf    config.WireGuardOptions
	host    host.Host
	key     crypto.PrivateKey
	tu      transport.Upgrader
	rcmgr   network.ResourceManager
	log     *slog.Logger
	iface   wireguard.Interface
	mu      sync.Mutex
}

func (t *LiteWebmeshTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.started.Load() {
		t.started.Store(false)
		return t.iface.Close(context.WithLogger(context.Background(), t.log))
	}
	return nil
}

// ConvertAddrs implements AddrsFactory on top of this transport. It automatically appends
// our webmesh ID and any DNS addresses we have to the list of addresses.
func (t *LiteWebmeshTransport) ConvertAddrs(addrs []ma.Multiaddr) []ma.Multiaddr {
	t.mu.Lock()
	defer t.mu.Unlock()
	webmeshSec := protocol.WithPeerID(t.key.ID())
	var out []ma.Multiaddr
	for _, addr := range addrs {
		out = append(out, ma.Join(addr, webmeshSec))
	}
	return out
}

// CanDial returns true if this transport knows how to dial the given
// multiaddr.
//
// Returning true does not guarantee that dialing this multiaddr will
// succeed. This function should *only* be used to preemptively filter
// out addresses that we can't dial.
func (t *LiteWebmeshTransport) CanDial(addr ma.Multiaddr) bool {
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
		return t.iface.NetworkV4().Contains(addr)
	}
	ip6addr, err := addr.ValueForProtocol(ma.P_IP6)
	if err == nil {
		addr, err := netip.ParseAddr(ip6addr)
		if err != nil {
			return false
		}
		return t.iface.NetworkV6().Contains(addr)
	}
	return false
}

// Dial dials a remote peer. It should try to reuse local listener
// addresses if possible, but it may choose not to.
func (t *LiteWebmeshTransport) Dial(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (transport.CapableConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.started.Load() {
		return nil, ErrNotStarted
	}
	return nil, nil
}

// Listen listens on the passed multiaddr.
func (t *LiteWebmeshTransport) Listen(laddr ma.Multiaddr) (transport.Listener, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	// ctx := context.WithLogger(context.Background(), t.log)
	return nil, nil
}

// Resolve attempts to resolve the given multiaddr to a list of addresses.
func (t *LiteWebmeshTransport) Resolve(ctx context.Context, maddr ma.Multiaddr) ([]ma.Multiaddr, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.started.Load() {
		return nil, ErrNotStarted
	}
	_ = context.WithLogger(ctx, t.log)
	return nil, nil
}

// Protocol returns the set of protocols handled by this transport.
func (t *LiteWebmeshTransport) Protocols() []int {
	return []int{protocol.Code}
}

// Proxy returns true if this is a proxy transport.
func (t *LiteWebmeshTransport) Proxy() bool {
	return true
}
