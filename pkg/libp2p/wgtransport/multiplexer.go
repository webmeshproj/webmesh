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
	"time"

	"github.com/libp2p/go-libp2p/core/network"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// Ensure we implement the interfaces.
var _ network.Multiplexer = (*Multiplexer)(nil)
var _ network.MuxedConn = (*MultiplexedConn)(nil)
var _ network.MuxedStream = (*TCPStream)(nil)

// Multiplexer is a multiplexer for libp2p connections.
type Multiplexer struct{}

// NewConn constructs a new connection
func (m *Multiplexer) NewConn(c net.Conn, isServer bool, scope network.PeerScope) (network.MuxedConn, error) {
	secureConn, ok := c.(*SecureConn)
	if !ok {
		return nil, fmt.Errorf("connection is not a wireguad secure connection")
	}
	log := secureConn.log
	log.Debug("Starting new multiplexed wireguard connection")
	mc := &MultiplexedConn{
		sc:      secureConn,
		streams: make(chan network.MuxedStream, 16),
		donec:   make(chan struct{}),
		log:     log,
	}
	go mc.acceptTCPStreams()
	return mc, nil
}

// MultiplexedConn is a connection that can be multiplexed
type MultiplexedConn struct {
	closed  atomic.Bool
	sc      *SecureConn
	streams chan network.MuxedStream
	donec   chan struct{}
	log     *slog.Logger
}

// Close closes the connection.
func (c *MultiplexedConn) Close() error {
	defer c.closed.Store(true)
	return c.sc.signals.Close()
}

// IsClosed returns whether a connection is fully closed, so it can
// be garbage collected.
func (c *MultiplexedConn) IsClosed() bool {
	return c.closed.Load()
}

// OpenStream opens a new stream.
func (c *MultiplexedConn) OpenStream(ctx context.Context) (network.MuxedStream, error) {
	return c.openTCPStream(ctx)
}

// AcceptStream accepts a stream opened by the other side.
func (c *MultiplexedConn) AcceptStream() (network.MuxedStream, error) {
	select {
	case <-c.donec:
		return nil, fmt.Errorf("connection closed")
	case stream := <-c.streams:
		return stream, nil
	}
}

func (c *MultiplexedConn) openTCPStream(ctx context.Context) (network.MuxedStream, error) {
	conn, err := c.sc.DialSignaler(ctx)
	if err != nil {
		c.log.Error("Failed to dial signaling server", "error", err.Error())
		return nil, fmt.Errorf("failed to connect for new stream: %w", err)
	}
	muxedStream := &TCPStream{TCPConn: conn}
	return muxedStream, nil
}

func (c *MultiplexedConn) acceptTCPStreams() {
	defer close(c.donec)
	defer c.closed.Store(true)
	for {
		conn, err := c.sc.AcceptSignal()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			c.log.Error("Failed to accept new stream", "error", err.Error())
			continue
		}
		c.streams <- &TCPStream{TCPConn: conn}
	}
}

// TCPStream is a multiplexed stream.
type TCPStream struct {
	*net.TCPConn
}

// CloseRead closes the stream for reading but leaves it open for
// writing.
//
// When CloseRead is called, all in-progress Read calls are interrupted with a non-EOF error and
// no further calls to Read will succeed.
//
// The handling of new incoming data on the stream after calling this function is implementation defined.
//
// CloseRead does not free the stream, users must still call Close or
// Reset.
func (s *TCPStream) CloseRead() error {
	// A bit of a hack but we just make all future reads fail.
	// The caller could technically remove this deadline but that's
	// not our problem.
	return s.TCPConn.SetReadDeadline(time.Now())
}

// CloseWrite closes the stream for writing but leaves it open for
// reading.
//
// CloseWrite does not free the stream, users must still call Close or
// Reset.
func (s *TCPStream) CloseWrite() error {
	// A bit of a hack but we just make all future writes fail.
	// The caller could technically remove this deadline but that's
	// not our problem.
	return s.TCPConn.SetWriteDeadline(time.Now())
}

// Reset closes both ends of the stream. Use this to tell the remote
// side to hang up and go away.
func (s *TCPStream) Reset() error {
	return s.TCPConn.Close()
}
