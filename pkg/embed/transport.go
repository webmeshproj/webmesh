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
	"net"
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
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/core/transport"
	"github.com/multiformats/go-multiaddr"
	mnet "github.com/multiformats/go-multiaddr/net"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/webmeshproj/webmesh/pkg/cmd/config"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
)

type Transport interface {
	io.Closer
	transport.Transport
}

// WithWebmeshTransport returns a libp2p option that configures the transport to use the embedded node.
func WithWebmeshTransport(config *config.Config) p2pconfig.Option {
	builder, transport := newTransportBuilder(config)
	return libp2p.ChainOptions(
		libp2p.DefaultTransports,
		libp2p.Transport(builder),
		libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			return transport, nil
		}),
	)
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

func newTransportBuilder(config *config.Config) (NewTransportFunc, *libp2pTransport) {
	t := &libp2pTransport{config: config}
	return func(upgrader transport.Upgrader, host host.Host, rcmgr network.ResourceManager, privKey p2pcrypto.PrivKey) (transport.Transport, error) {
		data, err := p2pcrypto.MarshalPrivateKey(privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		key, err := crypto.ParseKeyFromBytes(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		t.host = host
		t.upgrader = upgrader
		t.rcmgr = rcmgr
		t.key = key
		return t, nil
	}, t
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

// Dial dials a remote peer. It should try to reuse local listener addresses if possible, but it may choose not to.
func (l *libp2pTransport) Dial(ctx context.Context, raddr multiaddr.Multiaddr, p peer.ID) (transport.CapableConn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.started.Load() {
		return nil, errors.New("transport not started")
	}
	var dialer mnet.Dialer
	// TODO: Resolve webmesh addresses to their IP addresses
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
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.started.Load() {
		return false
	}
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
		inNetwork := l.node.Mesh().Network().NetworkV6().Contains(addr)
		return inNetwork
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
		if fqdn != "" {
			parts := strings.SplitN(fqdn, ".", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid webmesh address: %s", fullListener)
			}
			if l.config.Bootstrap.Enabled {
				l.config.Bootstrap.MeshDomain = parts[1]
			}
			l.config.Mesh.NodeID = parts[0]
		}
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
		_, err = l.node.Mesh().Storage().Subscribe(context.Background(), peers.NodesPrefix, func(key string, value string) {
			nodeID := strings.TrimPrefix(key, peers.NodesPrefix)
			if nodeID == l.node.Mesh().ID() {
				return
			}
			node := peers.MeshNode{MeshNode: &v1.MeshNode{}}
			err = protojson.Unmarshal([]byte(value), node.MeshNode)
			err := l.registerNode(context.Background(), node)
			if err != nil {
				context.LoggerFrom(ctx).Debug("Failed to register node to peerstore", "error", err.Error())
			}
		})
		if err != nil {
			return nil, fmt.Errorf("failed to subscribe to peers: %w", err)
		}
		nodes, err := peers.New(l.node.Mesh().Storage()).List(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to list peers: %w", err)
		}
		for _, node := range nodes {
			if node.Id == l.node.Mesh().ID() {
				continue
			}
			err := l.registerNode(context.Background(), node)
			if err != nil {
				context.LoggerFrom(ctx).Debug("Failed to register node to peerstore", "error", err.Error())
			}
		}
		l.started.Store(true)
	}
	ip6addr := multiaddr.StringCast(fmt.Sprintf("/ip6/%s", l.node.AddressV6().Addr().String()))
	lis, err := mnet.Listen(multiaddr.Join(ip6addr, listenAddr))
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}
	var addrs []multiaddr.Multiaddr
	var lisaddr multiaddr.Multiaddr
	switch v := lis.Addr().(type) {
	case *net.TCPAddr:
		lisaddr = multiaddr.StringCast(fmt.Sprintf("/tcp/%d", v.Port))
	case *net.UDPAddr:
		lisaddr = multiaddr.StringCast(fmt.Sprintf("/udp/%d", v.Port))
	}
	domaddr := multiaddr.StringCast(fmt.Sprintf("/webmesh/%s.%s", l.node.Mesh().ID(), strings.TrimSuffix(l.node.Mesh().Domain(), ".")))
	addrs = append(addrs, multiaddr.Join(domaddr, lisaddr))
	addrs = append(addrs, multiaddr.Join(ip6addr, lisaddr))
	// Broadcast the multiaddr to the network
	c, err := l.node.Mesh().DialLeader(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to dial leader: %w", err)
	}
	defer c.Close()
	_, err = v1.NewMembershipClient(c).Update(context.Background(), &v1.UpdateRequest{
		Id: l.node.Mesh().ID(),
		Multiaddrs: func() []string {
			var straddrs []string
			for _, addr := range addrs {
				straddrs = append(straddrs, addr.String())
			}
			return straddrs
		}(),
	})
	if err != nil {
		defer lis.Close()
		return nil, fmt.Errorf("failed to update membership: %w", err)
	}
	return l.upgrader.UpgradeListener(l, lis), nil
}

func (l *libp2pTransport) registerNode(ctx context.Context, node peers.MeshNode) error {
	ps := l.host.Peerstore()
	if node.GetHostPublicKey() == "" {
		return errors.New("missing public key")
	}
	pubkey, err := crypto.ParseHostPublicKey(node.GetHostPublicKey())
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}
	id, err := peer.IDFromPublicKey(pubkey)
	if err != nil {
		return fmt.Errorf("failed to get peer id: %w", err)
	}
	for _, addr := range node.GetMultiaddrs() {
		a, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			continue
		}
		ps.AddAddr(id, a, peerstore.PermanentAddrTTL)
	}
	return nil
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

func (l *libp2pTransport) FindPeer(ctx context.Context, peerID peer.ID) (peer.AddrInfo, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.started.Load() {
		return peer.AddrInfo{}, errors.New("transport not started")
	}
	pubKey, err := peerID.ExtractPublicKey()
	if err != nil {
		return peer.AddrInfo{}, fmt.Errorf("failed to extract public key: %w", err)
	}
	node, err := peers.New(l.node.Mesh().Storage()).GetByHostKey(ctx, pubKey)
	if err != nil {
		return peer.AddrInfo{}, fmt.Errorf("failed to get peer: %w", err)
	}
	var addrs []multiaddr.Multiaddr
	for _, addr := range node.GetMultiaddrs() {
		a, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			return peer.AddrInfo{}, fmt.Errorf("failed to parse multiaddr: %w", err)
		}
		addrs = append(addrs, a)
	}
	fmt.Println(addrs)
	return peer.AddrInfo{
		ID:    peerID,
		Addrs: addrs,
	}, nil
}

func (l *libp2pTransport) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	defer l.started.Store(false)
	if l.node != nil {
		return l.node.Stop(context.Background())
	}
	return nil
}
