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

// Package security implements the libp2p security transport for webmesh.
package security

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/sec"

	"github.com/webmeshproj/webmesh/pkg/context"
	wmcrypto "github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/embed/libp2p/util"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
	"github.com/webmeshproj/webmesh/pkg/util/netutil"
)

var _ sec.SecureTransport = (*SecureTransport)(nil)

// ID is the protocol ID of the security protocol.
const ID = "/webmesh/id/1.0.0"

// LiteSecureTransport provides a sec.SecureTransport that will automatically set up
// routes and compute addresses for peers as connections are opened.
type SecureTransport struct {
	peerID peer.ID
	key    wmcrypto.PrivateKey
	eps    []string
	iface  wireguard.Interface
	mu     sync.Mutex
}

// ID is the protocol ID of the security protocol.
func (l *SecureTransport) ID() protocol.ID { return ID }

// SetKey sets the private key to use for securing connections.
func (l *SecureTransport) SetKey(key wmcrypto.PrivateKey) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.key = key
	id, _ := peer.IDFromPrivateKey(key)
	l.peerID = id
}

// SetInterface sets the wireguard interface to use for securing connections.
func (l *SecureTransport) SetInterface(iface wireguard.Interface) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.iface = iface
}

// SetEndpoints sets the endpoints to use for securing connections.
func (l *SecureTransport) SetEndpoints(eps []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.eps = eps
}

// SecureInbound secures an inbound connection.
// If p is empty, connections from any peer are accepted.
func (l *SecureTransport) SecureInbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	log := context.LoggerFrom(ctx)
	if l.iface == nil {
		log.Error("SecureInbound called before WireGuard interface was set")
		return nil, fmt.Errorf("wireguard interface is not set")
	}
	log = log.With("remote-peer", p.String())
	log.Info("Securing inbound connection")
	if p == "" {
		// If the peer ID is empty, we don't know who this is, so we can't do anything
		// substantial for now.
		log.Debug("SecureInbound called with empty peer ID")
		return &SecureConn{
			Conn:      insecure,
			lpeer:     l.peerID,
			rpeer:     p,
			rkey:      nil,
			transport: util.GetTransport(insecure),
		}, nil
	}
	// Extract the public key from the peer ID.
	log.Debug("Extracting public key from peer ID")
	wmkey, err := util.ExtractWebmeshPublicKey(ctx, p)
	if err != nil {
		log.Error("Failed to convert public key to webmesh key", "error", err.Error())
		return nil, fmt.Errorf("failed to convert public key to webmesh key: %w", err)
	}
	// Configure wireguard for the peer.
	rula, raddr := netutil.GenerateULAWithKey(wmkey)
	err = l.iface.PutPeer(context.WithLogger(ctx, log), &wireguard.Peer{
		ID:        p.ShortString(),
		PublicKey: wmkey,
		// We expect the peer to invoke the stream handler for endpoint negotiation.
		Endpoint:    netip.AddrPort{},
		PrivateIPv6: netip.PrefixFrom(raddr, util.PrefixSize),
		AllowedIPs:  []netip.Prefix{rula},
	})
	if err != nil {
		log.Error("Failed to add peer to wireguard interface", "error", err.Error())
		return nil, fmt.Errorf("failed to add peer to wireguard interface: %w", err)
	}
	log.Info("Added peer to wireguard interface, waiting for endpoint negotiation")
	return &SecureConn{
		Conn:      insecure,
		lpeer:     l.peerID,
		rpeer:     p,
		rkey:      wmkey,
		transport: util.GetTransport(insecure),
	}, nil
}

// SecureOutbound secures an outbound connection.
func (l *SecureTransport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	log := context.LoggerFrom(ctx)
	if l.iface == nil {
		log.Error("SecureOutbound called before WireGuard interface was set")
		return nil, fmt.Errorf("wireguard interface is not set")
	}
	// Extract the peers public key from the peer ID.
	log = log.With("remote-peer", p.String())
	log.Info("Securing outbound connection")
	wmkey, err := util.ExtractWebmeshPublicKey(ctx, p)
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
		PrivateIPv6: netip.PrefixFrom(raddr, util.PrefixSize),
		AllowedIPs:  []netip.Prefix{rula},
	})
	if err != nil {
		log.Error("Failed to add peer to wireguard interface", "error", err.Error())
		return nil, fmt.Errorf("failed to add peer to wireguard interface: %w", err)
	}
	// We now need to try to negotiate endpoints with the remote peer via another
	// transport.
	log.Debug("Attempting endpoint negotiation")

	return &SecureConn{
		Conn:      insecure,
		lpeer:     l.peerID,
		rpeer:     p,
		rkey:      wmkey,
		transport: util.GetTransport(insecure),
	}, nil
}
