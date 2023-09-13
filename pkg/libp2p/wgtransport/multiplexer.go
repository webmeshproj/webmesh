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
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// Ensure we implement the interface
var _ network.Multiplexer = (*WireGuardMultiplexer)(nil)
var _ network.MuxedConn = (*Conn)(nil)
var _ network.MuxedStream = (*Stream)(nil)

// MuxerID is the ID of the wireguard multiplexer.
const MuxerID = "/webmesh/wireguard/1.0.0"

// Multiplexer is a ready to use multiplexer.
var Multiplexer = &WireGuardMultiplexer{}

// WireGuardMultiplexer is a multiplexer for libp2p connections.
type WireGuardMultiplexer struct{}

// NewStreamMagic is the magic string that is sent to the remote peer to indicate
// that a new stream is to be opened.
const NewStreamMagic = "WEBMESH_NEW_STREAM\n"

// NewConn constructs a new connection
func (m *WireGuardMultiplexer) NewConn(c net.Conn, isServer bool, scope network.PeerScope) (network.MuxedConn, error) {
	secureConn, ok := c.(*SecureConn)
	if !ok {
		return nil, fmt.Errorf("connection is not a wireguad secure connection")
	}
	log := secureConn.log
	log.Debug("Staring new multiplexed connection over wireguard")
	mc := &Conn{
		SecureConn: secureConn,
		peer:       scope.Peer(),
		log:        log,
	}
	mc.open.Store(true)
	return mc, nil
}

// Conn is a connection that can be multiplexed
type Conn struct {
	*SecureConn
	open atomic.Bool
	peer peer.ID
	log  *slog.Logger
}

// Close closes the connection.
func (c *Conn) Close() error {
	defer c.open.Store(false)
	return c.signals.Close()
}

// IsClosed returns whether a connection is fully closed, so it can
// be garbage collected.
func (c *Conn) IsClosed() bool {
	return !c.open.Load()
}

// OpenStream creates a new stream.
func (c *Conn) OpenStream(ctx context.Context) (network.MuxedStream, error) {
	c.log.Debug("Opening new stream, dialing signaling server")
	conn, err := c.SecureConn.DialSignaler(ctx)
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			c.open.Store(false)
		}
		c.log.Error("Failed to dial signaling server", "error", err.Error())
		return nil, fmt.Errorf("failed to dial signaling server: %w", err)
	}
	defer conn.Close()
	c.log.Debug("Established connection to signaling server")
	// Write the magic string
	_, err = conn.Write([]byte(NewStreamMagic))
	if err != nil {
		c.log.Error("Failed to write magic string", "error", err.Error())
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
				c.log.Error("Failed to set read deadline", "error", err.Error())
				return nil, fmt.Errorf("failed to set read deadline: %w", err)
			}
			n, err := conn.Read(buf[:])
			if err != nil || n == 0 {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					// If this is a timeout, continue
					continue WaitForStream
				}
				if err != nil {
					c.log.Error("Failed to read stream address", "error", err.Error())
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
		c.log.Error("Failed to parse stream address", "error", err.Error())
		return nil, fmt.Errorf("failed to parse stream address: %w", err)
	}
	c.log.Debug("Dialing stream address", "address", addr)
	// Dial the address
	stream, err := c.SecureConn.DialStream(ctx, addr)
	if err != nil {
		c.log.Error("Failed to dial stream", "error", err.Error())
		return nil, fmt.Errorf("failed to dial stream: %w", err)
	}
	muxedStream := &Stream{TCPConn: stream}
	return muxedStream, nil
}

// AcceptStream accepts a stream opened by the other side.
func (c *Conn) AcceptStream() (network.MuxedStream, error) {
	// Read the magic string
	conn, err := c.signals.Accept()
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			c.open.Store(false)
		}
		c.log.Error("Failed to accept new stream", "error", err.Error())
		return nil, fmt.Errorf("failed to accept new stream: %w", err)
	}
	defer conn.Close()
	c.log.Debug("Received new stream request")
	buf := make([]byte, len(NewStreamMagic))
	n, err := conn.Read(buf)
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			c.open.Store(false)
		}
		c.log.Error("Failed to read magic string", "error", err.Error())
		return nil, fmt.Errorf("failed to read magic string: %w", err)
	}
	magic := string(buf[:n])
	if magic != NewStreamMagic {
		c.log.Error("Invalid magic string", "magic", magic)
		return nil, fmt.Errorf("invalid magic string: %s", magic)
	}
	// We start a random UDP listener on our wireguard interface.
	// and pass it to the remote peer.
	stream, err := c.SecureConn.NewStreamListener()
	if err != nil {
		return nil, fmt.Errorf("failed to start stream listener: %w", err)
	}
	c.log.Debug("Started stream listener", "address", stream.Addr())
	// We write the address of the stream back to the remote peer.
	_, err = conn.Write([]byte(stream.Addr().String()))
	if err != nil {
		defer stream.Close()
		if errors.Is(err, net.ErrClosed) {
			c.open.Store(false)
		}
		c.log.Error("Failed to write stream address", "error", err.Error())
		return nil, fmt.Errorf("failed to write stream address: %w", err)
	}
	c.log.Debug("Waiting for stream to be dialed")
	muxconn, err := stream.Accept()
	if err != nil {
		defer stream.Close()
		if errors.Is(err, net.ErrClosed) {
			c.open.Store(false)
		}
		c.log.Error("Failed to accept stream", "error", err.Error())
		return nil, fmt.Errorf("failed to accept stream: %w", err)
	}
	muxedStream := &Stream{TCPConn: muxconn.(*net.TCPConn)}
	return muxedStream, nil
}
