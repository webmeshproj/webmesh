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

package wgtransport

import (
	"fmt"
	"net"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/pnet"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/sec"

	"github.com/webmeshproj/webmesh/pkg/context"
	wmcrypto "github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/libp2p/util"
)

// Ensure we implement the interface
var _ sec.SecureTransport = (*SecureTransport)(nil)

// SecureTransport provides a sec.SecureTransport that will automatically set up
// routes and compute addresses for peers as connections are opened.
type SecureTransport struct {
	peerID     peer.ID
	host       host.Host
	psk        pnet.PSK
	protocolID protocol.ID
	key        wmcrypto.PrivateKey
}

// New is a standalone constructor for SecureTransport.
func NewSecurity(id protocol.ID, host host.Host, psk pnet.PSK, privkey crypto.PrivKey) (*SecureTransport, error) {
	peerID, err := peer.IDFromPrivateKey(privkey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract peer ID from private key: %w", err)
	}
	key, err := util.ToWebmeshPrivateKey(privkey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert private key to webmesh key: %w", err)
	}
	sec := &SecureTransport{
		peerID:     peerID,
		host:       host,
		psk:        psk,
		protocolID: id,
		key:        key,
	}
	return sec, nil
}

// ID is the protocol ID of the security protocol.
func (st *SecureTransport) ID() protocol.ID { return st.protocolID }

// SecureInbound secures an inbound connection. If p is empty, connections from any peer are accepted.
func (st *SecureTransport) SecureInbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	return st.secureConn(ctx, insecure, p, network.DirInbound)
}

// SecureOutbound secures an outbound connection.
func (st *SecureTransport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	return st.secureConn(ctx, insecure, p, network.DirOutbound)
}

func (st *SecureTransport) secureConn(ctx context.Context, insecure net.Conn, p peer.ID, dir network.Direction) (sec.SecureConn, error) {
	wc, ok := insecure.(*Conn)
	if !ok {
		defer insecure.Close()
		return nil, fmt.Errorf("failed to secure connection: invalid connection type")
	}
	// We throw away the initial insecure connection no matter what and move it to wireguard
	log := context.LoggerFrom(wc.Context())
	ic := wc.Conn
	defer ic.Close()
	if dir == network.DirInbound {
		log.Debug("Securing inbound connection")
	} else {
		log.Debug("Securing outbound connection")
	}
	c, err := NewSecureConn(context.WithLogger(ctx, log), wc, p, st.psk, dir)
	if err != nil {
		log.Error("Failed to secure connection", "error", err.Error())
		return nil, fmt.Errorf("failed to secure connection: %w", err)
	}
	return c, nil
}
