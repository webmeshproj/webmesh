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

package wgsecurity

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/sec"

	"github.com/webmeshproj/webmesh/pkg/context"
	wgcrypto "github.com/webmeshproj/webmesh/pkg/crypto"
	wmproto "github.com/webmeshproj/webmesh/pkg/embed/libp2p/protocol"
	"github.com/webmeshproj/webmesh/pkg/embed/libp2p/util"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
	"github.com/webmeshproj/webmesh/pkg/util/netutil"
)

// Ensure we implement the interface
var _ sec.SecureConn = (*SecureConn)(nil)

// SecureConn is a simple wrapper around a sec.SecureConn that just holds the
// peer information.
type SecureConn struct {
	net.Conn
	rt       *SecureTransport
	signals  net.Listener
	rpeer    peer.ID
	rkey     wgcrypto.PublicKey
	protocol protocol.ID
	rula     netip.Prefix
	raddr    netip.Addr
}

// NewSecureConn upgrades an insecure connection with peer identity.
func (st *SecureTransport) NewSecureConn(ctx context.Context, insecure net.Conn, rpeer peer.ID) (*SecureConn, error) {
	log := context.LoggerFrom(ctx)
	var sc SecureConn
	var err error
	sc.Conn = insecure
	sc.rt = st
	log.Debug("Exchanging peer IDs over the wire")
	// Read the peer ID over the wire in a goroutine.
	errs := make(chan error, 1)
	go func() {
		defer close(errs)
		var buf [128]byte
		n, err := insecure.Read(buf[:])
		if n == 0 || err != nil {
			if err != nil {
				err = fmt.Errorf("failed to read peer ID from wire: %w", err)
			} else {
				err = fmt.Errorf("failed to read peer ID from wire, no data received")
			}
			errs <- err
			return
		}
		sc.rpeer = peer.ID(bytes.TrimSpace(buf[:n]))
		log.Debug("Read peer ID from wire", "peer", sc.rpeer.String())
		errs <- nil
	}()
	// Write our peer ID to the wire
	_, err = insecure.Write([]byte(st.peerID + "\n"))
	if err != nil {
		return nil, err
	}
	select {
	case err := <-errs:
		if err != nil {
			return nil, err
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// Try to extract the public key from the peer ID
	log.Debug("Extracting public key from peer ID", "peer", sc.rpeer.String())
	sc.rkey, err = util.ExtractWebmeshPublicKey(ctx, sc.rpeer)
	if err != nil {
		return nil, err
	}
	// Start a signaling listener for the connection
	addr := &net.TCPAddr{
		IP:   st.iface.AddressV6().Addr().AsSlice(),
		Port: wmproto.SignalingPort,
	}
	l, err := net.ListenTCP("tcp6", addr)
	if err != nil {
		return nil, err
	}
	log.Debug("Connection established, listening for new streams", "address", l.Addr().String())
	sc.signals = l
	return &sc, nil
}

// Context returns a context for this connection with an embedded logger
// and other peer information.
func (c *SecureConn) Context() context.Context {
	return context.WithLogger(context.Background(), c.rt.log.With("peer", c.rpeer.String()))
}

// Interface returns the interface backing this connection.
func (c *SecureConn) Interface() wireguard.Interface { return c.rt.iface }

// LocalPeer returns our peer ID
func (c *SecureConn) LocalPeer() peer.ID { return c.rt.peerID }

// RemotePeer returns the peer ID of the remote peer.
func (c *SecureConn) RemotePeer() peer.ID { return c.rpeer }

// RemotePublicKey returns the public key of the remote peer.
func (c *SecureConn) RemotePublicKey() crypto.PubKey { return c.rkey }

// ConnState returns information about the connection state.
func (c *SecureConn) ConnState() network.ConnectionState {
	return network.ConnectionState{
		Security:                  c.protocol,
		Transport:                 util.GetTransport(c),
		UsedEarlyMuxerNegotiation: true,
	}
}

// DialSignals dials the signaling server on the other side of this connection.
func (c *SecureConn) DialSignals(ctx context.Context) (*net.TCPConn, error) {
	addr := &net.TCPAddr{
		IP:   c.raddr.AsSlice(),
		Port: wmproto.SignalingPort,
	}
	c.rt.log.Debug("Dialing signaling server", "address", addr.String())
	var dialer net.Dialer
	dialer.LocalAddr = &net.TCPAddr{
		IP:   c.rt.iface.AddressV6().Addr().AsSlice(),
		Port: 0,
	}
	rc, err := dialer.DialContext(ctx, "tcp6", addr.String())
	if err != nil {
		return nil, err
	}
	return rc.(*net.TCPConn), nil
}

// NewStreamListener creates a new stream listener on this connection
// by allocating a random UDP port on the local wireguard interface.
func (c *SecureConn) NewStreamListener() (*net.TCPListener, error) {
	addr := &net.TCPAddr{
		IP:   c.rt.iface.AddressV6().Addr().AsSlice(),
		Port: 0,
	}
	return net.ListenTCP("tcp6", addr)
}

// DialStreamListener dials the stream listener on the other side of this connection.
func (c *SecureConn) DialStream(ctx context.Context, addr netip.AddrPort) (*net.TCPConn, error) {
	raddr := &net.TCPAddr{
		IP:   addr.Addr().AsSlice(),
		Port: int(addr.Port()),
	}
	var dialer net.Dialer
	dialer.LocalAddr = &net.TCPAddr{
		IP:   c.rt.iface.AddressV6().Addr().AsSlice(),
		Port: 0,
	}
	context.LoggerFrom(ctx).Debug("Dialing signaling stream", "address", raddr.String())
	rc, err := dialer.DialContext(ctx, "tcp6", raddr.String())
	if err != nil {
		return nil, err
	}
	return rc.(*net.TCPConn), nil
}

// ConfigureInterface configures the wireguard interface for this connection.
func (c *SecureConn) ConfigureInterface(ctx context.Context) error {
	log := context.LoggerFrom(ctx).With("peer", c.rpeer.String())
	if len(c.rt.psk) > 0 {
		// We seed the ULA with the PSK
		c.rula = netutil.GenerateULAWithSeed(c.rt.psk)
		c.raddr = netutil.AssignToPrefix(c.rula, c.rkey).Addr()
	} else {
		// The peer will have their own ULA that we'll trust.
		c.rula, c.raddr = netutil.GenerateULAWithKey(c.rkey)
	}
	log.Debug("Determined remote ULA and address for peer", "ula", c.rula.String(), "addr", c.raddr.String())
	peer := wireguard.Peer{
		ID:          c.rpeer.String(),
		PublicKey:   c.rkey,
		Endpoint:    netip.AddrPort{},
		PrivateIPv6: netip.PrefixFrom(c.raddr, wmproto.PrefixSize),
		AllowedIPs:  []netip.Prefix{c.rula},
	}
	log.Debug("Adding peer to wireguard interface", "config", peer)
	err := c.rt.iface.PutPeer(context.WithLogger(ctx, log), &peer)
	if err != nil {
		return fmt.Errorf("failed to add peer to wireguard interface: %w", err)
	}
	return nil
}

// EndpointsMessage is the message sent between peers to exchange endpoints.
type EndpointsMessage struct {
	// Endpoints is a comma-separated list of strings of the form
	// <addr>:<port> that the peer is listening on.
	Endpoints string
	// Signature is the signature of the endpoints string.
	Signature []byte
}

// ExchangeEndpoints exchanges endpoints with the remote peer.
func (c *SecureConn) ExchangeEndpoints(ctx context.Context) error {
	log := context.LoggerFrom(ctx)
	peer, ok := c.rt.iface.Peers()[c.rpeer.String()]
	if !ok {
		return fmt.Errorf("peer not found in wireguard interface")
	}
	log.Debug("Exchanging wireguard endpoints with peer")
	errs := make(chan error, 1)
	rw := bufio.NewReadWriter(bufio.NewReader(c.Conn), bufio.NewWriter(c.Conn))
	go func() {
		defer close(errs)
		log.Debug("Writing our endpoints to the peer", "endpoints", c.rt.eps)
		var msg EndpointsMessage
		if len(c.rt.eps) > 0 {
			data := strings.Join(c.rt.WireGuardAddrPorts(), ",")
			sig, err := c.rt.key.Sign([]byte(data))
			if err != nil {
				errs <- fmt.Errorf("failed to sign endpoints: %w", err)
				return
			}
			msg.Endpoints = data
			msg.Signature = sig
		}
		data, err := json.Marshal(msg)
		if err != nil {
			errs <- fmt.Errorf("failed to marshal endpoints: %w", err)
			return
		}
		_, err = rw.Write(append(data, []byte("\n")...))
		if err != nil {
			errs <- fmt.Errorf("failed to write endpoints: %w", err)
		}
		errs <- rw.Flush()
	}()
	log.Debug("Waiting for endpoints from the peer")
	data, err := rw.ReadBytes('\n')
	if err != nil {
		if len(data) == 0 || err != nil {
			if err != nil {
				err = fmt.Errorf("failed to read peer endpoints from wire: %w", err)
			} else {
				err = fmt.Errorf("failed to read peer endpoints from wire, no data received")
			}
			return err
		}
	}
	// Split the data into the endpoints and the signature.
	log.Debug("Received endpoint payload from peer, verifying signature")
	var msg EndpointsMessage
	err = json.Unmarshal(data, &msg)
	if err != nil {
		return fmt.Errorf("failed to unmarshal endpoints: %w", err)
	}
	if msg.Endpoints == "" {
		// Nothing to do
		log.Debug("Peer says they have no endpoints to add")
		return nil
	}
	log.Debug("Verifying signature on data", "endpoints", msg.Endpoints)
	ok, err = c.rkey.Verify([]byte(msg.Endpoints), msg.Signature)
	if err != nil {
		return fmt.Errorf("failed to verify endpoints signature: %w", err)
	}
	if !ok {
		return fmt.Errorf("peer endpoints signature is invalid")
	}
	// Parse the endpoints.
	epStrings := strings.Split(string(msg.Endpoints), ",")
	if len(epStrings) == 0 {
		// Nothing to do
		log.Debug("Peer says they have no endpoints to add")
		return nil
	}
	log.Debug("Peer sent us verified endpoints", "endpoints", epStrings)
	// Pick the first one in the list for now. But negotiation
	// should continue until a connection can be established.
	epString := epStrings[0]
	addrport, err := netip.ParseAddrPort(epString)
	if err != nil {
		log.Error("Failed to parse endpoint", "endpoint", epString, "error", err.Error())
		return fmt.Errorf("failed to parse endpoint %s: %w", epString, err)
	}
	peer.Endpoint = addrport
	err = c.rt.iface.PutPeer(ctx, &peer)
	if err != nil {
		log.Error("Failed to update peer in wireguard interface", "error", err.Error())
		return fmt.Errorf("failed to add peer to wireguard interface: %w", err)
	}
	return <-errs
}

// Close closes the connection. It removes the peer from the wireguard interface.
func (c *SecureConn) Close() error {
	defer c.signals.Close()
	// c.rt.log.Debug("Removing peer from wireguard interface", "peer", c.rpeer.String())
	// err := c.rt.iface.DeletePeer(context.Background(), c.rpeer.String())
	// if err != nil {
	// 	c.rt.log.Warn("Failed to remove peer from wireguard interface", "peer", c.rpeer.String(), "error", err.Error())
	// 	return fmt.Errorf("failed to remove peer from wireguard interface: %w", err)
	// }
	return nil
}
