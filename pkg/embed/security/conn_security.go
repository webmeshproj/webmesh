//go:build !wasm

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

// Package security defines a libp2p webmesh security transport.
package security

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	p2pproto "github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/sec"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
)

// ID is the protocol ID of the security protocol.
const ID = "/webmesh/id/1.0.0"

// Ensure we implement the interfaces.
var _ sec.SecureTransport = (*SecureTransport)(nil)
var _ sec.SecureConn = (*SecureConn)(nil)

// SecureTransportBuilder is the function signature returned from New
// for creating a secure transport.
type SecureTransportBuilder func(id p2pproto.ID, privkey p2pcrypto.PrivKey, host host.Host) (*SecureTransport, error)

// NewSecurity creates a new secure transport using the given wireguard interface.
func New(key crypto.PrivateKey, log *slog.Logger) (SecureTransportBuilder, *SecureTransport) {
	s := &SecureTransport{
		protocolID: ID,
		privateKey: key,
		log:        log,
	}
	return func(id p2pproto.ID, _ p2pcrypto.PrivKey, host host.Host) (*SecureTransport, error) {
		s.host = host
		s.ps = host.Peerstore()
		s.protocolID = id
		s.privateKey = key
		err := s.ps.AddProtocols(s.host.ID(), s.protocolID)
		if err != nil {
			return nil, fmt.Errorf("add protocol to peerstore: %w", err)
		}
		return s, nil
	}, s
}

// SecureTransport implements a libp2p secure transport using the local node's private key and WireGuard interface.
// It doesn't do much, but it's enough to make libp2p happy. WireGuard will not work if both sides haven't configured
// the same keys and allowed IPs.
type SecureTransport struct {
	host       host.Host
	ps         peerstore.Peerstore
	protocolID p2pproto.ID
	privateKey crypto.PrivateKey
	iface      wireguard.Interface
	log        *slog.Logger
	mu         sync.Mutex
}

// SetInterface sets the wireguard interface. The security transport will only accept connections
// from peers in the wireguard network.
func (s *SecureTransport) SetInterface(iface wireguard.Interface) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.iface = iface
}

// SecureInbound secures an inbound connection. If p is empty, connections from any peer are accepted.
func (s *SecureTransport) SecureInbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.iface == nil {
		return nil, errors.New("wireguard interface not set")
	}
	var remotePub p2pcrypto.PubKey
	var err error
	if p != "" {
		remotePub, err = crypto.ExtractPublicKeyFromID(p)
		if err != nil {
			return nil, fmt.Errorf("extract public key from peer ID: %w", err)
		}
	}
	inNw, err := s.IsInNetwork(insecure)
	if err != nil {
		return nil, fmt.Errorf("check inbound connection in network: %w", err)
	}
	if !inNw {
		return nil, fmt.Errorf("connection from %s not in wireguard network", insecure.RemoteAddr())
	}
	if p != "" {
		err := s.ps.AddProtocols(p, s.protocolID)
		if err != nil {
			return nil, fmt.Errorf("add protocol to peerstore: %w", err)
		}
	}
	return &SecureConn{
		Conn:         insecure,
		localID:      s.privateKey.ID(),
		remoteID:     p,
		remotePubkey: remotePub,
		transport:    getConnTransport(insecure),
	}, nil
}

// SecureOutbound secures an outbound connection.
func (s *SecureTransport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.iface == nil {
		return nil, errors.New("wireguard interface not set")
	}
	remotePub, err := crypto.ExtractPublicKeyFromID(p)
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key from peer ID: %w", err)
	}
	inNw, err := s.IsInNetwork(insecure)
	if err != nil {
		return nil, fmt.Errorf("check outbound connection in network: %w", err)
	}
	if !inNw {
		return nil, fmt.Errorf("connection to %s not in wireguard network", insecure.RemoteAddr())
	}
	if err := s.ps.AddProtocols(p, s.protocolID); err != nil {
		return nil, fmt.Errorf("add protocol to peerstore: %w", err)
	}
	return &SecureConn{
		Conn:         insecure,
		localID:      s.privateKey.ID(),
		remoteID:     p,
		remotePubkey: remotePub,
		transport:    getConnTransport(insecure),
	}, nil
}

// ID is the protocol ID of the security protocol.
func (s *SecureTransport) ID() p2pproto.ID {
	return s.protocolID
}

// IsInNetwork returns true if the given peer is in the wireguard network.
func (s *SecureTransport) IsInNetwork(c net.Conn) (bool, error) {
	raddr := c.RemoteAddr()
	switch v := raddr.(type) {
	case *net.UDPAddr:
		if !v.IP.IsLoopback() {
			if !s.iface.InNetwork(v.AddrPort().Addr()) {
				return false, nil
			}
		}
		return true, nil
	case *net.TCPAddr:
		if !v.IP.IsLoopback() {
			if !s.iface.InNetwork(v.AddrPort().Addr()) {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("unknown remote address type: %T", raddr)
	}
}

// SecureConn is a secure connection.
type SecureConn struct {
	net.Conn
	localID      peer.ID
	remoteID     peer.ID
	remotePubkey p2pcrypto.PubKey
	transport    string
}

// LocalPeer returns our peer ID
func (s *SecureConn) LocalPeer() peer.ID {
	return s.localID
}

// RemotePeer returns the peer ID of the remote peer.
func (s *SecureConn) RemotePeer() peer.ID {
	return s.remoteID
}

// RemotePublicKey returns the public key of the remote peer.
func (s *SecureConn) RemotePublicKey() p2pcrypto.PubKey {
	return s.remotePubkey
}

// ConnState returns information about the connection state.
func (s *SecureConn) ConnState() network.ConnectionState {
	return network.ConnectionState{
		Security:                  ID,
		Transport:                 s.transport,
		UsedEarlyMuxerNegotiation: false,
	}
}

func getConnTransport(c net.Conn) string {
	switch c.(type) {
	case *net.TCPConn:
		return "tcp"
	case *net.UDPConn:
		return "udp"
	default:
		return "unknown"
	}
}
