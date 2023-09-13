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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/sec"

	"github.com/webmeshproj/webmesh/pkg/context"
	wgcrypto "github.com/webmeshproj/webmesh/pkg/crypto"
	wmproto "github.com/webmeshproj/webmesh/pkg/libp2p/protocol"
	p2putil "github.com/webmeshproj/webmesh/pkg/libp2p/util"
)

// Ensure we implement the interface
var _ sec.SecureConn = (*SecureConn)(nil)

// SecureConn is a simple wrapper around a sec.SecureConn that just holds the
// peer information.
type SecureConn struct {
	net.Conn
	rt       *Transport
	signals  net.Listener
	rsignalp int
	rpeer    peer.ID
	rkey     wgcrypto.PublicKey
	raddr    netip.Addr
	protocol protocol.ID
}

// LocalPeer returns our peer ID
func (c *SecureConn) LocalPeer() peer.ID { return c.rt.peerID }

// RemotePeer returns the peer ID of the remote peer.
func (c *SecureConn) RemotePeer() peer.ID { return c.rpeer }

// RemotePublicKey returns the public key of the remote peer.
func (c *SecureConn) RemotePublicKey() crypto.PubKey { return c.rkey }

// ConnState returns information about the connection state.
func (c *SecureConn) ConnState() network.ConnectionState {
	return network.ConnectionState{
		StreamMultiplexer:         wmproto.ProtocolID,
		Security:                  wmproto.SecurityID,
		Transport:                 "tcp",
		UsedEarlyMuxerNegotiation: true,
	}
}

// DialSignals dials the signaling server on the other side of this connection.
func (c *SecureConn) DialSignaler(ctx context.Context) (*net.TCPConn, error) {
	addr := &net.TCPAddr{
		IP:   c.raddr.AsSlice(),
		Port: c.rsignalp,
	}
	context.LoggerFrom(ctx).Debug("Dialing signaling server", "address", addr.String())
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

// EndpointsMessage is the message sent between peers to exchange endpoints.
type EndpointsMessage struct {
	// Endpoints is a comma-separated list of strings of the form
	// <addr>:<port> that the peer is listening on.
	Endpoints string
	// Signature is the signature of the endpoints string.
	Signature []byte
}

func (c *SecureConn) Close() error {
	defer func() {
		err := c.rt.iface.DeletePeer(context.Background(), c.rpeer.String())
		if err != nil {
			c.rt.log.Warn("Failed to delete peer from wireguard interface", "error", err.Error())
		}
	}()
	defer c.signals.Close()
	return c.Conn.Close()
}

func (c *SecureConn) exchangePeerIDs(ctx context.Context, rpeer peer.ID) error {
	log := context.LoggerFrom(ctx)
	log.Debug("Exchanging peer IDs over the wire")
	// Read the peer ID over the wire in a goroutine.
	errs := make(chan error, 1)
	go func() {
		defer close(errs)
		var buf [128]byte
		n, err := c.Read(buf[:])
		if n == 0 || err != nil {
			if err != nil {
				err = fmt.Errorf("failed to read peer ID from wire: %w", err)
			} else {
				err = fmt.Errorf("failed to read peer ID from wire, no data received")
			}
			errs <- err
			return
		}
		c.rpeer = peer.ID(bytes.TrimSpace(buf[:n]))
		log.Debug("Read peer ID from wire, extracting public key", "peer", c.rpeer.String())
		// Try to extract the public key from the peer ID
		c.rkey, err = p2putil.ExtractWebmeshPublicKey(ctx, c.rpeer)
		if err != nil {
			errs <- fmt.Errorf("failed to extract public key from peer ID: %w", err)
			return
		}
		// If we came in expecting a specific peer ID, make sure it matches
		if rpeer != "" && c.rpeer != rpeer {
			errs <- fmt.Errorf("expected peer ID %s, got %s", rpeer, c.rpeer)
			return
		}
		errs <- nil
	}()
	// Write our peer ID to the wire
	_, err := c.Conn.Write([]byte(c.rt.peerID + "\n"))
	if err != nil {
		return fmt.Errorf("failed to write peer ID to wire: %w", err)
	}
	// Wait for the goroutine
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errs:
		if err != nil {
			return err
		}
	}
	// Extract the peer's public key
	log.Debug("Extracting peer public key", "peer", c.rpeer.String())
	key, err := p2putil.ExtractWebmeshPublicKey(ctx, c.rpeer)
	if err != nil {
		return fmt.Errorf("failed to extract peer public key: %w", err)
	}
	c.rkey = key
	return nil
}

func (c *SecureConn) exchangeSignalingPorts(ctx context.Context) error {
	log := context.LoggerFrom(ctx)
	// Do a signaling server exchange
	log.Debug("Exchanging signaling server addresses")

	// Start a signaling listener for the connection
	addr := &net.TCPAddr{
		IP:   c.rt.iface.AddressV6().Addr().AsSlice(),
		Port: 0,
	}
	// TODO: Listen according to the transport.
	l, err := net.ListenTCP("tcp6", addr)
	if err != nil {
		return fmt.Errorf("failed to start signaling server: %w", err)
	}
	// Read the remote port in a goroutine
	errs := make(chan error, 1)
	go func() {
		var buf [128]byte
		n, err := c.Read(buf[:])
		if n == 0 || err != nil {
			if err != nil {
				err = fmt.Errorf("failed to read signaling port from wire: %w", err)
			} else {
				err = fmt.Errorf("failed to read signaling port from wire, no data received")
			}
			errs <- err
			return
		}
		c.rsignalp, err = strconv.Atoi(string(bytes.TrimSpace(buf[:n])))
		if err != nil {
			errs <- fmt.Errorf("failed to parse signaling port: %w", err)
			return
		}
		log.Debug("Received remote peer signal port", "port", c.rsignalp)
		// TODO: Sign and verify this value (though we sign our endpoint negotiation later on)
		errs <- nil
	}()

	log.Debug("Sending our signaling address to remote peer", "address", l.Addr().String())
	// Write our listening port over the wire
	_, err = c.Write([]byte(fmt.Sprintf("%d\n", l.Addr().(*net.TCPAddr).Port)))
	if err != nil {
		defer l.Close()
		return fmt.Errorf("failed to write signaling port to wire: %w", err)
	}
	// Wait on the goroutine
	select {
	case <-ctx.Done():
		defer l.Close()
		return ctx.Err()
	case err := <-errs:
		if err != nil {
			defer l.Close()
			return err
		}
	}
	c.signals = l
	log.Debug("Listening for new streams", "address", l.Addr().String())
	return nil
}

// exchangeEndpoints exchanges endpoints with the remote peer.
func (c *SecureConn) exchangeEndpoints(ctx context.Context) (endpoint netip.AddrPort, err error) {
	log := context.LoggerFrom(ctx)
	log.Debug("Exchanging wireguard endpoints with peer")
	rw := bufio.NewReadWriter(bufio.NewReader(c.Conn), bufio.NewWriter(c.Conn))
	go func() {
		eps := c.rt.WireGuardEndpoints()
		log.Debug("Writing our endpoints to the peer", "endpoints", eps)
		var msg EndpointsMessage
		if len(c.rt.eps) > 0 {
			data := strings.Join(eps, ",")
			sig, err := c.rt.key.Sign([]byte(data))
			if err != nil {
				log.Error("Failed to sign endpoints", "error", err.Error())
				return
			}
			msg.Endpoints = data
			msg.Signature = sig
		}
		data, err := json.Marshal(msg)
		if err != nil {
			log.Error("Failed to marshal endpoints", "error", err.Error())
			return
		}
		_, err = rw.Write(append(data, []byte("\n")...))
		if err != nil {
			log.Error("Failed to write endpoints to peer", "error", err.Error())
			return
		}
		err = rw.Flush()
		if err != nil {
			log.Error("Failed to flush endpoints to peer", "error", err.Error())
			return
		}
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
			return
		}
	}
	// Split the data into the endpoints and the signature.
	log.Debug("Received endpoint payload from peer, verifying signature")
	var msg EndpointsMessage
	err = json.Unmarshal(data, &msg)
	if err != nil {
		err = fmt.Errorf("failed to unmarshal endpoints: %w", err)
		return
	}
	if msg.Endpoints == "" {
		// Nothing to do
		log.Debug("Peer says they have no endpoints to add")
		return
	}
	log.Debug("Verifying signature on data", "endpoints", msg.Endpoints)
	ok, err := c.rkey.Verify([]byte(msg.Endpoints), msg.Signature)
	if err != nil {
		err = fmt.Errorf("failed to verify endpoints signature: %w", err)
	} else if !ok {
		err = fmt.Errorf("peer endpoints signature is invalid")
	}
	if err != nil {
		return
	}
	// Parse the endpoints.
	epStrings := strings.Split(string(msg.Endpoints), ",")
	if len(epStrings) == 0 {
		// Nothing to do
		log.Debug("Peer says they have no endpoints to add")
		return endpoint, nil
	}
	log.Debug("Peer sent us verified endpoints", "endpoints", epStrings)
	// Pick the first one in the list for now. But negotiation
	// should continue until a connection can be established.
	epString := epStrings[0]
	addrport, err := netip.ParseAddrPort(epString)
	if err != nil {
		log.Error("Failed to parse endpoint", "endpoint", epString, "error", err.Error())
		return endpoint, fmt.Errorf("failed to parse endpoint %s: %w", epString, err)
	}
	endpoint = addrport
	return
}
