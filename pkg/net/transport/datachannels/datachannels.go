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

// Package datachannels provides a WebRTC data channel API for port forwarding.
package datachannels

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pion/datachannel"
	"github.com/pion/webrtc/v3"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/util"
)

// ManagedServerChannel is a channel that is managed for a particular purpose.
// This is currently used for the WireGuard proxy and the port-forwarding
// data channels.
type ManagedServerChannel interface {
	// Offer returns the offer for the data channel.
	Offer() string
	// AnswerOffer answers the offer from the peer.
	AnswerOffer(offer string) error
	// Candidates returns a channel for receiving ICE candidates.
	Candidates() <-chan string
	// AddCandidate adds an ICE candidate.
	AddCandidate(candidate string) error
	// Closed returns a channel for receiving a notification when the data channel is closed.
	Closed() <-chan struct{}
	// Close closes the data channel.
	Close() error
}

// ServerChannel is a server-side data channel.
type ServerChannel interface {
	// Accept accepts a new connection channel.
	Accept() (proto string, rw io.ReadWriteCloser, err error)
	// Ready returns a channel that is closed when the data channel is ready.
	Ready() <-chan struct{}
	// Errors returns a channel for receiving errors.
	Errors() <-chan error
	// Closed returns a channel for receiving a notification when the data channel is closed.
	Closed() <-chan struct{}
	// Close closes the data channel.
	Close() error
}

// DefaultWireGuardProxyBuffer is the default buffer size for the WireGuard proxy.
// TODO: Make this configurable.
const DefaultWireGuardProxyBuffer = 1024 * 1024

// NewServerChannel creates a new server-side data channel.
func NewServerChannel(ctx context.Context, rt transport.WebRTCSignalTransport) (ServerChannel, error) {
	log := context.LoggerFrom(ctx)
	log.Debug("Starting signaling transport")
	err := rt.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start signaling transport: %w", err)
	}
	s := webrtc.SettingEngine{}
	s.DetachDataChannels()
	s.SetIncludeLoopbackCandidate(true)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))
	p, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: rt.TURNServers(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create peer connection: %w", err)
	}
	c := &serverChannel{
		PeerConnection: p,
		errors:         make(chan error, 5),
		ready:          make(chan struct{}),
		closed:         make(chan struct{}),
		acceptc:        make(chan clientConn, 5),
	}
	c.OnICECandidate(func(cand *webrtc.ICECandidate) {
		if cand == nil {
			return
		}
		err := rt.SendCandidate(ctx, cand.ToJSON())
		if err != nil && err != transport.ErrSignalTransportClosed {
			c.errors <- fmt.Errorf("failed to send ICE candidate: %w", err)
		}
	})
	c.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		log.Debug("Peer connection state has changed", "state", state.String())
		if state == webrtc.PeerConnectionStateConnected {
			defer rt.Close()
		}
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			defer c.Close()
			close(c.closed)
		}
	})
	// Create the negotiation data channel
	dc, err := c.CreateDataChannel(v1.DataChannel_CHANNELS.String(), &webrtc.DataChannelInit{
		Protocol:   util.Pointer("tcp"),
		Ordered:    util.Pointer(true),
		Negotiated: util.Pointer(true),
		ID:         util.Pointer(uint16(0)),
	})
	if err != nil {
		defer c.Close()
		return nil, fmt.Errorf("failed to create negotiation data channel: %w", err)
	}
	dc.OnOpen(func() {
		log.Debug("Negotiation data channel opened")
		defer close(c.ready)
		detached, err := dc.Detach()
		if err != nil {
			defer c.Close()
			c.errors <- fmt.Errorf("failed to detach negotiation data channel: %w", err)
			return
		}
		rw := detached.(*datachannel.DataChannel)
		neg := bufio.NewReadWriter(bufio.NewReader(rw), bufio.NewWriter(rw))
		// Listen for incoming connections
		go func() {
			for {
				var connNumber uint32
				err := binary.Read(neg, binary.BigEndian, &connNumber)
				if err != nil {
					defer c.Close()
					c.errors <- fmt.Errorf("failed to read connection number: %w", err)
					return
				}
				// Read the protocol
				proto, err := neg.ReadString('\n')
				if err != nil {
					defer c.Close()
					c.errors <- fmt.Errorf("failed to read protocol: %w", err)
					return
				}
				// Strip the trailing newline
				proto = strings.TrimSuffix(proto, "\n")
				log := log.With("conn-number", connNumber).With("protocol", proto)
				log.Info("received incoming connection, creating channel")
				d, err := c.CreateDataChannel(
					v1.DataChannel_CONNECTIONS.String(), &webrtc.DataChannelInit{
						Protocol: func() *string {
							if proto == "" {
								return nil
							}
							return util.Pointer(proto)
						}(),
						Ordered:    util.Pointer(true),
						Negotiated: util.Pointer(true),
						ID:         util.Pointer(uint16(connNumber)),
					},
				)
				if err != nil {
					defer c.Close()
					c.errors <- fmt.Errorf("failed to create data channel: %w", err)
					return
				}
				d.OnClose(func() {
					log.Debug("Connection data channel closed")
				})
				d.OnOpen(func() {
					log.Debug("Data channel has opened, detaching")
					conn, err := d.Detach()
					if err != nil {
						defer c.Close()
						c.errors <- fmt.Errorf("failed to detach data channel: %w", err)
						return
					}
					c.acceptc <- clientConn{
						rw:    conn,
						proto: proto,
					}
				})
			}
		}()
	})
	dc.OnClose(func() {
		log.Debug("Negotiation data channel closed")
	})
	// Send an offer to the peer
	offer, err := c.CreateOffer(nil)
	if err != nil {
		defer c.Close()
		return nil, fmt.Errorf("failed to create offer: %w", err)
	}
	err = c.SetLocalDescription(offer)
	if err != nil {
		defer c.Close()
		return nil, fmt.Errorf("failed to set local description: %w", err)
	}
	err = rt.SendDescription(ctx, offer)
	if err != nil {
		defer c.Close()
		return nil, fmt.Errorf("failed to send offer: %w", err)
	}
	err = c.SetRemoteDescription(rt.RemoteDescription())
	if err != nil {
		defer c.Close()
		return nil, fmt.Errorf("failed to set remote description: %w", err)
	}
	// Handle ICE candidiates
	go func() {
		for cand := range rt.Candidates() {
			err := c.AddICECandidate(cand)
			if err != nil {
				defer c.Close()
				c.errors <- fmt.Errorf("failed to add ICE candidate: %w", err)
				return
			}
		}
	}()
	return c, nil
}

type serverChannel struct {
	// PeerConnection is the underlying WebRTC peer connection.
	*webrtc.PeerConnection
	// errors is a channel for receiving errors from the peer connection.
	errors chan error
	// acceptc is a channel for receiving incoming connections.
	acceptc chan clientConn
	// ready is a channel for receiving a notification when the peer connection is ready.
	ready chan struct{}
	// closed is a channel for receiving a notification when the peer connection is closed.
	closed chan struct{}
}

type clientConn struct {
	rw    io.ReadWriteCloser
	proto string
}

// Accept accepts a new connection channel.
func (s *serverChannel) Accept() (proto string, rw io.ReadWriteCloser, err error) {
	select {
	case <-s.ready:
	case <-s.closed:
		return "", nil, net.ErrClosed
	case <-s.errors:
		return "", nil, net.ErrClosed
	}
	select {
	case <-s.closed:
		return "", nil, net.ErrClosed
	case <-s.errors:
		return "", nil, net.ErrClosed
	case conn := <-s.acceptc:
		return conn.proto, conn.rw, nil
	}
}

// Ready returns a channel that is closed when the data channel is ready.
func (s *serverChannel) Ready() <-chan struct{} { return s.ready }

// Errors returns a channel for receiving errors.
func (s *serverChannel) Errors() <-chan error { return s.errors }

// Closed returns a channel for receiving a notification when the data channel is closed.
func (s *serverChannel) Closed() <-chan struct{} { return s.closed }

// Close closes the data channel.
func (s *serverChannel) Close() error {
	return s.PeerConnection.Close()
}

// ClientChannel is a client-side data channel.
type ClientChannel interface {
	// Ready returns a channel that is closed when the data channel is ready.
	Ready() <-chan struct{}
	// Errors returns a channel for receiving errors.
	Errors() <-chan error
	// Closed returns a channel for receiving a notification when the data channel is closed.
	Closed() <-chan struct{}
	// Open opens a new data channel.
	Open(ctx context.Context, proto string) (io.ReadWriteCloser, error)
	// Close closes the peer connection and all data channels.
	Close() error
}

// NewClientChannel creates a new client-side data channel.
func NewClientChannel(ctx context.Context, rt transport.WebRTCSignalTransport) (ClientChannel, error) {
	log := context.LoggerFrom(ctx)
	log.Debug("Starting signaling transport")
	err := rt.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start signaling transport: %w", err)
	}
	s := webrtc.SettingEngine{}
	s.DetachDataChannels()
	s.SetIncludeLoopbackCandidate(true)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))
	p, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: rt.TURNServers(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create peer connection: %w", err)
	}
	c := &clientChannel{
		PeerConnection: p,
		errors:         make(chan error, 5),
		ready:          make(chan struct{}),
		closed:         make(chan struct{}),
	}
	c.OnICECandidate(func(cand *webrtc.ICECandidate) {
		if cand == nil {
			return
		}
		err := rt.SendCandidate(ctx, cand.ToJSON())
		if err != nil && err != transport.ErrSignalTransportClosed {
			c.errors <- fmt.Errorf("failed to send ICE candidate: %w", err)
		}
	})
	c.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		log.Debug("Peer connection state has changed", "state", state.String())
		if state == webrtc.PeerConnectionStateConnected {
			defer rt.Close()
		}
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			defer c.Close()
			close(c.closed)
		}
	})
	// Create the negotiation data channel
	dc, err := c.CreateDataChannel(v1.DataChannel_CHANNELS.String(), &webrtc.DataChannelInit{
		Protocol:   util.Pointer("tcp"),
		Ordered:    util.Pointer(true),
		Negotiated: util.Pointer(true),
		ID:         util.Pointer(uint16(0)),
	})
	if err != nil {
		defer c.Close()
		return nil, fmt.Errorf("failed to create negotiation data channel: %w", err)
	}
	dc.OnOpen(func() {
		log.Debug("Negotiation data channel opened")
		defer close(c.ready)
		detached, err := dc.Detach()
		if err != nil {
			defer c.Close()
			c.errors <- fmt.Errorf("failed to detach negotiation data channel: %w", err)
			return
		}
		rw := detached.(*datachannel.DataChannel)
		c.neg = bufio.NewReadWriter(bufio.NewReader(rw), bufio.NewWriter(rw))
	})
	dc.OnClose(func() {
		log.Debug("Negotiation data channel closed")
	})
	// Send an offer to the peer
	offer, err := c.CreateOffer(nil)
	if err != nil {
		defer c.Close()
		return nil, fmt.Errorf("failed to create offer: %w", err)
	}
	err = c.SetLocalDescription(offer)
	if err != nil {
		defer c.Close()
		return nil, fmt.Errorf("failed to set local description: %w", err)
	}
	err = rt.SendDescription(ctx, offer)
	if err != nil {
		defer c.Close()
		return nil, fmt.Errorf("failed to send offer: %w", err)
	}
	err = c.SetRemoteDescription(rt.RemoteDescription())
	if err != nil {
		defer c.Close()
		return nil, fmt.Errorf("failed to set remote description: %w", err)
	}
	// Handle ICE candidiates
	go func() {
		for cand := range rt.Candidates() {
			err := c.AddICECandidate(cand)
			if err != nil {
				defer c.Close()
				c.errors <- fmt.Errorf("failed to add ICE candidate: %w", err)
				return
			}
		}
	}()
	return c, nil
}

type clientChannel struct {
	// PeerConnection is the underlying WebRTC peer connection.
	*webrtc.PeerConnection
	// neg is the negotiation datachannel
	neg *bufio.ReadWriter
	// count is the number of connections opened. It is used for
	// incrementing the connection channel ID.
	count atomic.Uint32
	// errors is a channel for receiving errors from the peer connection.
	errors chan error
	// ready is a channel for receiving a notification when the peer connection is ready.
	ready chan struct{}
	// closed is a channel for receiving a notification when the peer connection is closed.
	closed chan struct{}
	// mu is a mutex for synchronizing access to the data channels.
	mu sync.Mutex
}

// Ready returns a channel that is closed when the data channel is ready.
func (c *clientChannel) Ready() <-chan struct{} { return c.ready }

// Errors returns a channel for receiving errors.
func (c *clientChannel) Errors() <-chan error { return c.errors }

// Closed returns a channel for receiving a notification when the data channel is closed.
func (c *clientChannel) Closed() <-chan struct{} { return c.closed }

// Open opens a new data channel.
func (c *clientChannel) Open(ctx context.Context, proto string) (io.ReadWriteCloser, error) {
	c.mu.Lock()
	log := context.LoggerFrom(ctx)
	connNumber := c.count.Add(1)
	// Write the connection number followed by the protocol
	log.Debug("Opening connection data channel", "conn-number", connNumber)
	if err := binary.Write(c.neg, binary.BigEndian, connNumber); err != nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("failed to write to negotiation data channel: %w", err)
	}
	if _, err := c.neg.Write(append([]byte(proto), []byte("\n")...)); err != nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("failed to write to negotiation data channel: %w", err)
	}
	if err := c.neg.Flush(); err != nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("failed to flush negotiation data channel: %w", err)
	}
	d, err := c.CreateDataChannel(
		v1.DataChannel_CONNECTIONS.String(), &webrtc.DataChannelInit{
			Protocol: func() *string {
				if proto == "" {
					return nil
				}
				return util.Pointer(proto)
			}(),
			Ordered:    util.Pointer(true),
			Negotiated: util.Pointer(true),
			ID:         util.Pointer(uint16(connNumber)),
		},
	)
	c.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("failed to create data channel: %w", err)
	}
	d.OnClose(func() {
		log.Debug("Connection data channel closed", "conn-number", connNumber)
	})
	acceptc := make(chan io.ReadWriteCloser)
	errc := make(chan error)
	d.OnOpen(func() {
		rw, err := d.Detach()
		if err != nil {
			errc <- fmt.Errorf("failed to detach data channel: %w", err)
			return
		}
		acceptc <- rw
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errc:
		return nil, err
	case rw := <-acceptc:
		return rw, nil
	}
}

// Close closes the peer connection and all data channels.
func (c *clientChannel) Close() error {
	return c.PeerConnection.Close()
}
