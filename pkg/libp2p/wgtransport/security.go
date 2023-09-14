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
	"net/netip"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/pnet"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/sec"

	"github.com/webmeshproj/webmesh/pkg/context"
	wmcrypto "github.com/webmeshproj/webmesh/pkg/crypto"
	wmproto "github.com/webmeshproj/webmesh/pkg/libp2p/protocol"
	"github.com/webmeshproj/webmesh/pkg/libp2p/util"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
	"github.com/webmeshproj/webmesh/pkg/util/netutil"
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
	// Set the negotiation handler for the security protocol.
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
	// We throw away the initial insecure connection no matter what and move it to wireguard
	defer insecure.Close()
	wc, ok := insecure.(*WebmeshConn)
	if !ok {
		return nil, fmt.Errorf("failed to secure outbound connection: invalid connection type")
	}
	log := context.LoggerFrom(wc.Context())
	log.Debug("Securing inbound connection")
	c, err := st.NewSecureConn(context.WithLogger(ctx, log), wc, p)
	if err != nil {
		log.Error("Failed to secure connection", "error", err.Error())
		return nil, fmt.Errorf("failed to secure connection: %w", err)
	}
	return c, nil
}

// SecureOutbound secures an outbound connection.
func (st *SecureTransport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	// We throw away the initial insecure connection no matter what and move it to wireguard
	defer insecure.Close()
	wc, ok := insecure.(*WebmeshConn)
	if !ok {
		return nil, fmt.Errorf("failed to secure outbound connection: invalid connection type")
	}
	log := context.LoggerFrom(wc.Context())
	log.Debug("Securing outbound connection")
	c, err := st.NewSecureConn(context.WithLogger(ctx, log), wc, p)
	if err != nil {
		log.Error("Failed to secure connection", "error", err.Error())
		return nil, fmt.Errorf("failed to secure connection: %w", err)
	}
	return c, nil
}

// NewSecureConn upgrades an insecure connection with peer identity.
func (st *SecureTransport) NewSecureConn(ctx context.Context, insecure *WebmeshConn, rpeer peer.ID) (*SecureConn, error) {
	log := context.LoggerFrom(ctx)
	sc := &SecureConn{}
	sc.WebmeshConn = insecure
	sc.protocol = wmproto.SecurityID
	sc.log = log
	// Do the negotiation exchange
	log.Debug("Performing security negotiation")
	endpoint, err := sc.negotiate(ctx, st.psk)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange endpoints: %w", err)
	}
	// Determine expected remote addresses and configure wireguard.
	var rula netip.Prefix
	if len(st.psk) > 0 {
		// We seed the ULA with the PSK
		rula = netutil.GenerateULAWithSeed(st.psk)
		sc.raddr = netutil.AssignToPrefix(rula, sc.rkey).Addr()
	} else {
		// The peer will have their own ULA that we'll trust.
		rula, sc.raddr = netutil.GenerateULAWithKey(sc.rkey)
	}
	log.Debug("Determined remote ULA and address for peer", "ula", rula.String(), "addr", sc.raddr.String())
	peer := wireguard.Peer{
		ID:          sc.rpeer.String(),
		PublicKey:   sc.rkey,
		Endpoint:    endpoint,
		PrivateIPv6: netip.PrefixFrom(sc.raddr, wmproto.PrefixSize),
		AllowedIPs:  []netip.Prefix{rula},
	}
	log.Debug("Adding peer to wireguard interface", "config", peer)
	err = insecure.iface.PutPeer(context.WithLogger(ctx, log), &peer)
	if err != nil {
		return nil, fmt.Errorf("failed to add peer to wireguard interface: %w", err)
	}
	return sc, nil
}
