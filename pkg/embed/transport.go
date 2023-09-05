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

package embed

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/libp2p/go-libp2p"
	p2pconfig "github.com/libp2p/go-libp2p/config"
	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/transport"
	"github.com/multiformats/go-multiaddr"
	mnet "github.com/multiformats/go-multiaddr/net"

	"github.com/webmeshproj/webmesh/pkg/cmd/config"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
)

type Transport interface {
	io.Closer
	transport.Transport
}

// WithWebmeshTransport returns a libp2p option that configures the transport to use the embedded node.
func WithWebmeshTransport(config *config.Config) p2pconfig.Option {
	return libp2p.ChainOptions(libp2p.DefaultTransports, libp2p.Transport(NewTransport(config)))
}

// NewTransportFunc is the signature of a function that returns a new transport.
type NewTransportFunc func(upgrader transport.Upgrader, host host.Host, rcmgr network.ResourceManager, privKey p2pcrypto.PrivKey) (transport.Transport, error)

// NewTransport returns a libp2p compatible transport backed by an embedded node.
func NewTransport(config *config.Config) NewTransportFunc {
	return func(upgrader transport.Upgrader, host host.Host, rcmgr network.ResourceManager, privKey p2pcrypto.PrivKey) (transport.Transport, error) {
		data, err := p2pcrypto.MarshalPrivateKey(privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		key, err := crypto.ParseKeyFromBytes(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		return &libp2pTransport{
			config:   config,
			host:     host,
			upgrader: upgrader,
			rcmgr:    rcmgr,
			key:      key,
		}, nil
	}
}

type libp2pTransport struct {
	config   *config.Config
	host     host.Host
	upgrader transport.Upgrader
	rcmgr    network.ResourceManager
	key      crypto.Key
	node     Node
	started  atomic.Bool
	mu       sync.Mutex
}

// Dial dials a remote peer. It should try to reuse local listener
// addresses if possible, but it may choose not to.
func (l *libp2pTransport) Dial(ctx context.Context, raddr multiaddr.Multiaddr, p peer.ID) (transport.CapableConn, error) {
	var dialer mnet.Dialer
	c, err := dialer.DialContext(ctx, raddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	connScope, err := l.rcmgr.OpenConnection(network.DirOutbound, false, raddr)
	if err != nil {
		return nil, fmt.Errorf("failed to open connection: %w", err)
	}
	u, err := l.upgrader.Upgrade(ctx, l, c, network.DirOutbound, p, connScope)
	if err != nil {
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
func (l *libp2pTransport) CanDial(addr multiaddr.Multiaddr) bool {
	// Check if it's a webmesh address
	_, err := addr.ValueForProtocol(ProtocolCode)
	if err == nil {
		return true
	}
	// We can do ip4/ip6 dialing if they are within our network.
	ip4addr, err := addr.ValueForProtocol(multiaddr.P_IP4)
	if err == nil {
		addr, err := netip.ParseAddr(ip4addr)
		if err != nil {
			return false
		}
		return l.node.Mesh().Network().NetworkV4().Contains(addr)
	}
	ip6addr, err := addr.ValueForProtocol(multiaddr.P_IP6)
	if err == nil {
		addr, err := netip.ParseAddr(ip6addr)
		if err != nil {
			return false
		}
		return l.node.Mesh().Network().NetworkV6().Contains(addr)
	}
	return false
}

// Listen listens on the passed multiaddr.
func (l *libp2pTransport) Listen(laddr multiaddr.Multiaddr) (transport.Listener, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	spl := multiaddr.Split(laddr)
	if len(spl) == 1 {
		// No listening address was provided
		return nil, errors.New("no listening address provided")
	}
	listenAddr := multiaddr.Join(spl[1:]...)
	if !l.started.Load() {
		fullListener, err := laddr.ValueForProtocol(ProtocolCode)
		if err != nil {
			return nil, fmt.Errorf("multiaddr does not contain a webmesh address: %w", err)
		}
		fqdn := strings.TrimPrefix(fullListener, "/")
		parts := strings.SplitN(fqdn, ".", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid webmesh address: %s", fullListener)
		}
		if l.config.Bootstrap.Enabled {
			l.config.Bootstrap.MeshDomain = parts[1]
		}
		l.config.Mesh.NodeID = parts[0]
		err = l.config.Validate()
		if err != nil {
			return nil, fmt.Errorf("invalid configuration: %w", err)
		}
		ctx := context.Background()
		l.node, err = NewNodeWithKey(ctx, l.config, l.key)
		if err != nil {
			return nil, fmt.Errorf("failed to create node: %w", err)
		}
		err = l.node.Start(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to start node: %w", err)
		}
		l.started.Store(true)
	}
	ipaddr := multiaddr.StringCast(fmt.Sprintf("/ip6/%s", l.node.AddressV6().Addr().String()))
	ipListener := multiaddr.Join(ipaddr, listenAddr)
	lis, err := mnet.Listen(ipListener)
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}
	return l.upgrader.UpgradeListener(l, lis), nil
}

// Protocol returns the set of protocols handled by this transport.
//
// See the Network interface for an explanation of how this is used.
func (l *libp2pTransport) Protocols() []int {
	return []int{ProtocolCode}
}

// Proxy returns true if this is a proxy transport.
func (l *libp2pTransport) Proxy() bool {
	return true
}

// Close closes the transport.
func (l *libp2pTransport) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	defer l.started.Store(false)
	if l.node != nil {
		return l.node.Stop(context.Background())
	}
	return nil
}
