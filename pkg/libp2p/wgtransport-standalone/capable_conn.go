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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/transport"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// Ensure we satisfy the interface.
var _ transport.CapableConn = (*CapableConn)(nil)

// NewStreamMagic is the magic string that is sent to the signaling server
// to request a new stream.
const NewStreamMagic = "WEBMESH_NEW_STREAM\n"

// CapableConn is a webmesh capable connection.
type CapableConn struct {
	sc             *SecureConn
	rt             *Transport
	closed         atomic.Bool
	scope          network.ConnManagementScope
	lmaddr, rmaddr ma.Multiaddr
}

// Transport returns the underlying transport.
func (c *CapableConn) Transport() transport.Transport {
	return c.rt
}

// Scoped returns the connection's scope.
func (c *CapableConn) Scope() network.ConnScope {
	return c.scope
}

// IsClosed returns whether a connection is fully closed, so it can
// be garbage collected.
func (c *CapableConn) IsClosed() bool {
	return c.closed.Load()
}

// LocalMultiaddr returns the local Multiaddr associated
// with this connection
func (c *CapableConn) LocalMultiaddr() ma.Multiaddr {
	return c.lmaddr
}

// RemoteMultiaddr returns the remote Multiaddr associated
// with this connection
func (c *CapableConn) RemoteMultiaddr() ma.Multiaddr {
	return c.rmaddr
}

// LocalPeer returns our peer ID
func (c *CapableConn) LocalPeer() peer.ID {
	return c.sc.LocalPeer()
}

// RemotePeer returns the peer ID of the remote peer.
func (c *CapableConn) RemotePeer() peer.ID {
	return c.sc.RemotePeer()
}

// RemotePublicKey returns the public key of the remote peer.
func (c *CapableConn) RemotePublicKey() crypto.PubKey {
	return c.sc.RemotePublicKey()
}

// ConnState returns information about the connection state.
func (c *CapableConn) ConnState() network.ConnectionState {
	return c.sc.ConnState()
}

// Close closes the connection.
func (c *CapableConn) Close() error {
	defer c.closed.Store(true)
	return c.sc.signals.Close()
}

// OpenStream creates a new stream.
func (c *CapableConn) OpenStream(ctx context.Context) (network.MuxedStream, error) {
	log := context.LoggerFrom(ctx)
	log.Debug("Opening new stream, dialing signaling server")
	conn, err := c.sc.DialSignaler(ctx)
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			c.closed.Store(true)
		}
		log.Error("Failed to dial signaling server", "error", err.Error())
		return nil, fmt.Errorf("failed to dial signaling server: %w", err)
	}
	defer conn.Close()
	log.Debug("Established connection to signaling server")
	// Write the magic string
	_, err = conn.Write([]byte(NewStreamMagic))
	if err != nil {
		log.Error("Failed to write magic string", "error", err.Error())
		return nil, fmt.Errorf("failed to write magic string: %w", err)
	}
	// Wait for the address we are going to dial
	// The response will be an IPv6 address and port
	buf := make([]byte, 1024)
WaitForStream:
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("failed to read stream address: context canceled")
		default:
			err := conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			if err != nil {
				log.Error("Failed to set read deadline", "error", err.Error())
				return nil, fmt.Errorf("failed to set read deadline: %w", err)
			}
			n, err := conn.Read(buf[:])
			if err != nil || n == 0 {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					// If this is a timeout, continue
					continue WaitForStream
				}
				if err != nil {
					log.Error("Failed to read stream address", "error", err.Error())
					return nil, fmt.Errorf("failed to read stream address: %w", err)
				}
				return nil, fmt.Errorf("failed to read stream address: no data")
			}
			buf = buf[:n]
			break WaitForStream
		}
	}
	addr, err := netip.ParseAddrPort(strings.TrimSpace(string(buf)))
	if err != nil {
		log.Error("Failed to parse stream address", "error", err.Error())
		return nil, fmt.Errorf("failed to parse stream address: %w", err)
	}
	log.Debug("Dialing stream address", "address", addr)
	// Dial the address
	stream, err := c.sc.DialStream(ctx, addr)
	if err != nil {
		log.Error("Failed to dial stream", "error", err.Error())
		return nil, fmt.Errorf("failed to dial stream: %w", err)
	}
	muxedStream := &MuxedStream{TCPConn: stream}
	return muxedStream, nil
}

// AcceptStream accepts a stream opened by the other side.
func (c *CapableConn) AcceptStream() (network.MuxedStream, error) {
	log := c.rt.log
	// Read the magic string
	conn, err := c.sc.signals.Accept()
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			c.closed.Store(true)
		}
		log.Error("Failed to accept new stream", "error", err.Error())
		return nil, fmt.Errorf("failed to accept new stream: %w", err)
	}
	defer conn.Close()
	log.Debug("Received new stream request")
	buf := make([]byte, len(NewStreamMagic))
	n, err := conn.Read(buf)
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			c.closed.Store(true)
		}
		log.Error("Failed to read magic string", "error", err.Error())
		return nil, fmt.Errorf("failed to read magic string: %w", err)
	}
	magic := string(buf[:n])
	if magic != NewStreamMagic {
		log.Error("Invalid magic string", "magic", magic)
		return nil, fmt.Errorf("invalid magic string: %s", magic)
	}
	// We start a random UDP listener on our wireguard interface.
	// and pass it to the remote peer.
	stream, err := c.sc.NewStreamListener()
	if err != nil {
		return nil, fmt.Errorf("failed to start stream listener: %w", err)
	}
	log.Debug("Started stream listener", "address", stream.Addr())
	// We write the address of the stream back to the remote peer.
	_, err = conn.Write([]byte(stream.Addr().String()))
	if err != nil {
		defer stream.Close()
		if errors.Is(err, net.ErrClosed) {
			c.closed.Store(true)
		}
		log.Error("Failed to write stream address", "error", err.Error())
		return nil, fmt.Errorf("failed to write stream address: %w", err)
	}
	log.Debug("Waiting for stream to be dialed")
	muxconn, err := stream.Accept()
	if err != nil {
		defer stream.Close()
		if errors.Is(err, net.ErrClosed) {
			c.closed.Store(true)
		}
		log.Error("Failed to accept stream", "error", err.Error())
		return nil, fmt.Errorf("failed to accept stream: %w", err)
	}
	muxedStream := &MuxedStream{TCPConn: muxconn.(*net.TCPConn)}
	return muxedStream, nil
}
