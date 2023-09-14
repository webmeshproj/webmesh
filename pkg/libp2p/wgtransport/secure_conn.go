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
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/sec"

	"github.com/webmeshproj/webmesh/pkg/context"
	wgcrypto "github.com/webmeshproj/webmesh/pkg/crypto"
	wmproto "github.com/webmeshproj/webmesh/pkg/libp2p/protocol"
	p2putil "github.com/webmeshproj/webmesh/pkg/libp2p/util"
	"github.com/webmeshproj/webmesh/pkg/util/netutil"
)

// Ensure we implement the interface
var _ sec.SecureConn = (*SecureConn)(nil)

// SecureConn is a simple wrapper around a sec.SecureConn that just holds the
// peer information.
type SecureConn struct {
	*WebmeshConn
	lsignals net.Listener
	rsignalp int
	rpeer    peer.ID
	rkey     wgcrypto.PublicKey
	rula     netip.Prefix
	raddr    netip.Addr
	protocol protocol.ID
}

// LocalPeer returns our peer ID
func (c *SecureConn) LocalPeer() peer.ID { return c.WebmeshConn.lpeer }

// RemotePeer returns the peer ID of the remote peer.
func (c *SecureConn) RemotePeer() peer.ID { return c.rpeer }

// RemotePublicKey returns the public key of the remote peer.
func (c *SecureConn) RemotePublicKey() crypto.PubKey { return c.rkey }

// ConnState returns information about the connection state.
func (c *SecureConn) ConnState() network.ConnectionState {
	return network.ConnectionState{
		StreamMultiplexer:         MuxerID,
		Security:                  wmproto.SecurityID,
		Transport:                 "udp",
		UsedEarlyMuxerNegotiation: true,
	}
}

// DialSignaler dials the signaler on the other side of this connection.
func (c *SecureConn) DialSignaler(ctx context.Context) (*net.TCPConn, error) {
	var dialer net.Dialer
	dialer.LocalAddr = &net.TCPAddr{
		IP:   c.iface.AddressV6().Addr().AsSlice(),
		Port: 0,
	}
	raddr := &net.TCPAddr{
		IP:   c.raddr.AsSlice(),
		Port: c.rsignalp,
	}
	context.LoggerFrom(ctx).Debug("Dialing signaling stream", "address", raddr.String())
	rc, err := dialer.DialContext(ctx, "tcp6", raddr.String())
	if err != nil {
		return nil, err
	}
	return rc.(*net.TCPConn), nil
}

type Negotiation struct {
	// PeerID is the peer ID of the remote peer.
	PeerID peer.ID
	// Endpoints is a comma-separated list of strings of the form
	// <addr>:<port> that the peer is listening on.
	Endpoints []string
	// SignalPort is the port that the peer is listening for signaling
	// new streams on.
	SignalPort int
	// Signature which should equal this payload without the signature
	// appended as a base64-encoded string.
	Signature string
}

// negotiate handles the initial negotiation of the connection.
func (c *SecureConn) negotiate(ctx context.Context, psk pnet.PSK) (netip.AddrPort, error) {
	// Read remote message in a goroutine
	log := context.LoggerFrom(ctx)
	var remoteEndpoint netip.AddrPort
	log.Debug("Starting signaling server")
	addr := &net.TCPAddr{
		IP:   c.iface.AddressV6().Addr().AsSlice(),
		Port: 0,
	}
	l, err := net.ListenTCP("tcp6", addr)
	if err != nil {
		return remoteEndpoint, fmt.Errorf("failed to start signaling server: %w", err)
	}
	c.lsignals = l
	log.Debug("Signaling server started, handling negotiation", "address", l.Addr().String())
	errs := make(chan error, 1)
	go func() {
		defer close(errs)
		log.Debug("Waiting for negotiation payload")
		var msg Negotiation
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
		c.rsignalp = msg.SignalPort
		c.rpeer = msg.PeerID
		c.WebmeshConn.rmaddr = wmproto.Encapsulate(c.WebmeshConn.Conn.RemoteMultiaddr(), c.rpeer)
		if len(psk) > 0 {
			// We seed the ULA with the PSK
			c.rula = netutil.GenerateULAWithSeed(psk)
			c.raddr = netutil.AssignToPrefix(c.rula, c.rkey).Addr()
		} else {
			// The peer will have their own ULA that we'll trust.
			c.rula, c.raddr = netutil.GenerateULAWithKey(c.rkey)
		}
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
	payload := Negotiation{
		PeerID:     c.WebmeshConn.lpeer,
		Endpoints:  c.WebmeshConn.eps,
		SignalPort: l.Addr().(*net.TCPAddr).Port,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return remoteEndpoint, fmt.Errorf("failed to marshal negotiation payload: %w", err)
	}
	// Sign the payload
	sig, err := c.lkey.Sign(data)
	if err != nil {
		return remoteEndpoint, fmt.Errorf("failed to sign negotiation payload: %w", err)
	}
	// Remarshal with the signature
	payload.Signature = base64.RawStdEncoding.EncodeToString(sig)
	data, err = json.Marshal(payload)
	if err != nil {
		return remoteEndpoint, fmt.Errorf("failed to marshal negotiation payload: %w", err)
	}
	_, err = c.Write(data)
	if err != nil {
		return remoteEndpoint, fmt.Errorf("failed to write negotiation payload to wire: %w", err)
	}
	// Wait for the goroutine
	select {
	case <-ctx.Done():
		return remoteEndpoint, ctx.Err()
	case err = <-errs:
	}
	return remoteEndpoint, err
}
