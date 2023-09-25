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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/pnet"
	"github.com/libp2p/go-libp2p/core/sec"
	mnet "github.com/multiformats/go-multiaddr/net"

	"github.com/webmeshproj/webmesh/pkg/context"
	wgcrypto "github.com/webmeshproj/webmesh/pkg/crypto"
	wmproto "github.com/webmeshproj/webmesh/pkg/libp2p/protocol"
	p2putil "github.com/webmeshproj/webmesh/pkg/libp2p/util"
	netutil "github.com/webmeshproj/webmesh/pkg/meshnet/util"
	"github.com/webmeshproj/webmesh/pkg/meshnet/wireguard"
)

// Ensure we implement the interface
var _ sec.SecureConn = (*SecureConn)(nil)

// SecureConn is a simple wrapper around the underlying connection that
// holds remote peer information.
type SecureConn struct {
	*Conn
	rpeer peer.ID
	rkey  wgcrypto.PublicKey
}

// NewSecureConn upgrades an insecure connection with peer identity.
func NewSecureConn(ctx context.Context, insecure *Conn, rpeer peer.ID, psk pnet.PSK, dir network.Direction) (*SecureConn, error) {
	log := context.LoggerFrom(ctx)
	sc := &SecureConn{
		Conn: insecure,
	}
	log.Debug("Performing security negotiation")
	err := sc.negotiate(ctx, psk, dir)
	if err != nil {
		return nil, fmt.Errorf("failed to negotiate wireguard connection: %w", err)
	}
	return sc, nil
}

// LocalPeer returns our peer ID
func (c *SecureConn) LocalPeer() peer.ID { return c.Conn.lpeer }

// RemotePeer returns the peer ID of the remote peer.
func (c *SecureConn) RemotePeer() peer.ID { return c.rpeer }

// RemotePublicKey returns the public key of the remote peer.
func (c *SecureConn) RemotePublicKey() crypto.PubKey { return c.rkey }

// ConnState returns information about the connection state.
func (c *SecureConn) ConnState() network.ConnectionState {
	return network.ConnectionState{
		Security:                  wmproto.SecurityID,
		Transport:                 "tcp",
		UsedEarlyMuxerNegotiation: false,
	}
}

type negotiation struct {
	// PeerID is the peer ID of the remote peer.
	PeerID peer.ID
	// Endpoints is a comma-separated list of strings of the form
	// <addr>:<port> that the peer is listening on.
	Endpoints []string
	// SecurePort is the port that the incoming secure connection should
	// be established on.
	SecurePort int
	// Signature which should equal this payload without the signature
	// appended as a base64-encoded string.
	Signature string
}

// negotiate handles the initial negotiation of the connection.
func (c *SecureConn) negotiate(ctx context.Context, psk pnet.PSK, dir network.Direction) (err error) {
	var (
		rula           netip.Prefix
		raddr          netip.Addr
		remoteEndpoint netip.AddrPort
		ln             net.Listener
		securep        int
	)
	laddr := &net.TCPAddr{
		IP:   c.iface.AddressV6().Addr().AsSlice(),
		Port: 0,
	}
	log := context.LoggerFrom(ctx)
	if dir == network.DirInbound {
		log.Debug("Starting secure listener")
		ln, err = net.ListenTCP("tcp6", laddr)
		if err != nil {
			err = fmt.Errorf("failed to start signaling server: %w", err)
			return
		}
		defer ln.Close()
		securep = ln.Addr().(*net.TCPAddr).Port
		log.Debug("Secure listener started, handling negotiation", "address", ln.Addr().String())
	}
	errs := make(chan error, 1)
	go func() {
		defer close(errs)
		log.Debug("Waiting for negotiation payload")
		var msg negotiation
		err := json.NewDecoder(c).Decode(&msg)
		if err != nil {
			errs <- fmt.Errorf("failed to decode negotiation payload: %w", err)
			return
		}
		log.Debug("Received negotiation payload, verifying the signature")
		// Marshal the payload and verify the signature
		sig, err := base64.RawStdEncoding.DecodeString(msg.Signature)
		if err != nil {
			errs <- fmt.Errorf("failed to decode negotiation signature: %w", err)
			return
		}
		msg.Signature = ""
		data, err := json.Marshal(msg)
		if err != nil {
			log.Error("Failed to marshal negotiation payload", "error", err.Error())
			errs <- fmt.Errorf("failed to marshal negotiation payload: %w", err)
			return
		}
		// Extract the public key from the peer ID
		key, err := p2putil.ExtractWebmeshPublicKey(ctx, msg.PeerID)
		if err != nil {
			log.Error("Failed to extract public key from peer ID", "error", err.Error())
			errs <- fmt.Errorf("failed to extract public key from peer ID: %w", err)
			return
		}
		c.rkey = key
		ok, err := c.rkey.Verify(data, sig)
		if err != nil {
			log.Error("Failed to verify negotiation signature", "error", err.Error())
			errs <- fmt.Errorf("failed to verify negotiation signature: %w", err)
			return
		}
		if !ok {
			log.Error("Negotiation signature is invalid")
			errs <- fmt.Errorf("negotiation signature is invalid")
			return
		}
		log.Debug("Negotiation signature is valid")
		if dir == network.DirOutbound {
			securep = msg.SecurePort
		}
		c.rpeer = msg.PeerID
		c.Conn.rmaddr = wmproto.Encapsulate(c.Conn.Conn.RemoteMultiaddr(), c.rpeer)
		if len(psk) > 0 {
			// We seed the ULA with the PSK
			rula = netutil.GenerateULAWithSeed(psk)
			raddr = netutil.AssignToPrefix(rula, c.rkey).Addr()
		} else {
			// The peer will have their own ULA that we'll trust.
			rula, raddr = netutil.GenerateULAWithKey(c.rkey)
		}
		log.Debug("Determined remote network addresses for for peer",
			"ula", rula.String(),
			"addr", raddr.String(),
		)
		if len(msg.Endpoints) == 0 {
			// We're done here
			errs <- nil
			return
		}
		// We just use the first one for now
		epString := msg.Endpoints[0]
		remoteEndpoint, err = netip.ParseAddrPort(epString)
		errs <- err
	}()
	payload := negotiation{
		PeerID:     c.Conn.lpeer,
		Endpoints:  c.Conn.eps,
		SecurePort: securep,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		err = fmt.Errorf("failed to marshal negotiation payload: %w", err)
		return
	}
	// Sign the payload
	sig, err := c.lkey.Sign(data)
	if err != nil {
		err = fmt.Errorf("failed to sign negotiation payload: %w", err)
		return
	}
	// Remarshal with the signature
	payload.Signature = base64.RawStdEncoding.EncodeToString(sig)
	data, err = json.Marshal(payload)
	if err != nil {
		err = fmt.Errorf("failed to marshal negotiation payload: %w", err)
		return
	}
	_, err = c.Write(data)
	if err != nil {
		err = fmt.Errorf("failed to write negotiation payload to wire: %w", err)
		return
	}
	// Wait for the goroutine
	select {
	case <-ctx.Done():
		err = ctx.Err()
		return
	case err = <-errs:
		if err != nil {
			err = fmt.Errorf("failed to complete negotiation: %w", err)
			return
		}
	}
	// Configure WireGuard
	peer := wireguard.Peer{
		ID:          c.rpeer.String(),
		PublicKey:   c.rkey,
		Endpoint:    remoteEndpoint,
		PrivateIPv6: netip.PrefixFrom(raddr, wmproto.PrefixSize),
		AllowedIPs:  []netip.Prefix{rula},
	}
	log.Debug("Adding peer to wireguard interface", "config", peer)
	err = c.iface.PutPeer(context.WithLogger(ctx, log), &peer)
	if err != nil {
		err = fmt.Errorf("failed to add peer to wireguard interface: %w", err)
		return
	}
	// Create the secure connection
	log.Debug("Creating secure connection over WireGuard")
	if dir == network.DirInbound {
		sc, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept secure connection: %w", err)
		}
		c.Conn.Conn, err = mnet.WrapNetConn(sc)
		if err != nil {
			return fmt.Errorf("failed to wrap secure connection: %w", err)
		}
	} else {
		sc, err := net.DialTCP("tcp6", laddr, &net.TCPAddr{
			IP:   raddr.AsSlice(),
			Port: securep,
		})
		if err != nil {
			return fmt.Errorf("failed to dial secure connection: %w", err)
		}
		c.Conn.Conn, err = mnet.WrapNetConn(sc)
		if err != nil {
			return fmt.Errorf("failed to wrap secure connection: %w", err)
		}
	}
	return
}
