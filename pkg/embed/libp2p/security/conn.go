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
	"net"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/sec"

	wmproto "github.com/webmeshproj/webmesh/pkg/embed/libp2p/protocol"
)

var _ sec.SecureConn = (*SecureConn)(nil)

// SecureConn is a simple wrapper around a sec.SecureConn that just holds the
// peer information.
type SecureConn struct {
	net.Conn
	lpeer     peer.ID
	rpeer     peer.ID
	rkey      crypto.PubKey
	transport string
}

// LocalPeer returns our peer ID
func (l *SecureConn) LocalPeer() peer.ID { return l.lpeer }

// RemotePeer returns the peer ID of the remote peer.
func (l *SecureConn) RemotePeer() peer.ID { return l.rpeer }

// RemotePublicKey returns the public key of the remote peer.
func (l *SecureConn) RemotePublicKey() crypto.PubKey { return l.rkey }

// ConnState returns information about the connection state.
func (l *SecureConn) ConnState() network.ConnectionState {
	return network.ConnectionState{
		Security:                  wmproto.SecurityID,
		Transport:                 l.transport,
		UsedEarlyMuxerNegotiation: false,
	}
}
