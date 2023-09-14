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
	"sync/atomic"

	"github.com/libp2p/go-libp2p/core/network"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// Ensure we implement the interface
var _ network.Multiplexer = (*WireGuardMultiplexer)(nil)
var _ network.MuxedConn = (*Conn)(nil)

// MuxerID is the ID of the wireguard multiplexer.
const MuxerID = "/webmesh/wireguard/1.0.0"

// Multiplexer is a ready to use multiplexer.
var Multiplexer = &WireGuardMultiplexer{}

// WireGuardMultiplexer is a multiplexer for libp2p connections.
type WireGuardMultiplexer struct{}

// NewConn constructs a new connection
func (m *WireGuardMultiplexer) NewConn(c net.Conn, isServer bool, scope network.PeerScope) (network.MuxedConn, error) {
	secureConn, ok := c.(*SecureConn)
	if !ok {
		return nil, fmt.Errorf("connection is not a wireguad secure connection")
	}
	log := secureConn.log
	log.Debug("Starting new multiplexed wireguard connection")
	mc := &Conn{
		sc:      secureConn,
		streams: make(chan network.MuxedStream, 16),
		donec:   make(chan struct{}),
		log:     log,
	}
	// go mc.acceptIPStreams()
	go mc.acceptTCPStreams()
	return mc, nil
}

// Conn is a connection that can be multiplexed
type Conn struct {
	closed  atomic.Bool
	sc      *SecureConn
	streams chan network.MuxedStream
	donec   chan struct{}
	log     *slog.Logger
}

// Close closes the connection.
func (c *Conn) Close() error {
	defer c.closed.Store(true)
	return c.sc.lsignals.Close()
}

// IsClosed returns whether a connection is fully closed, so it can
// be garbage collected.
func (c *Conn) IsClosed() bool {
	return c.closed.Load()
}

// OpenStream opens a new stream.
func (c *Conn) OpenStream(ctx context.Context) (network.MuxedStream, error) {
	return c.openTCPStream(ctx)
}

// AcceptStream accepts a stream opened by the other side.
func (c *Conn) AcceptStream() (network.MuxedStream, error) {
	select {
	case <-c.donec:
		return nil, fmt.Errorf("connection closed")
	case stream := <-c.streams:
		return stream, nil
	}
}

// OpenStream creates a new stream.
func (c *Conn) openTCPStream(ctx context.Context) (network.MuxedStream, error) {
	conn, err := c.sc.DialSignaler(ctx)
	if err != nil {
		c.log.Error("Failed to dial signaling server", "error", err.Error())
		return nil, fmt.Errorf("failed to connect for new stream: %w", err)
	}
	muxedStream := &TCPStream{TCPConn: conn}
	return muxedStream, nil
}

func (c *Conn) acceptTCPStreams() {
	defer close(c.donec)
	defer c.closed.Store(true)
	for {
		conn, err := c.sc.lsignals.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			c.log.Error("Failed to accept new stream", "error", err.Error())
			continue
		}
		c.streams <- &TCPStream{TCPConn: conn.(*net.TCPConn)}
	}
}
