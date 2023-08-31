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

package datachannels

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"

	"github.com/pion/datachannel"
	"github.com/pion/webrtc/v3"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/util"
)

// ClientOptions are options for configuring a client peer connection.
type ClientOptions struct {
	// Client is the webmesh client for performing ICE negotiation.
	Client v1.WebRTCClient
	// NodeID is the node ID to request for connection channels.
	NodeID string
	// Protocol is the protocol to request for connection channels.
	Protocol string
	// Destination is the destination address to request for connection channels.
	Destination string
	// Port is the destination port to request for connection channels.
	// A port of 0 with the udp protocol indicates WireGuard interface traffic.
	Port uint32
}

// PeerConnectionClient is a WebRTC peer connection for port forwarding.
type PeerConnectionClient struct {
	// PeerConnection is the underlying WebRTC peer connection.
	*webrtc.PeerConnection
	// protocol is the protocol to use for connection channels.
	protocol string
	// neg is the negotiation stream
	rt transport.WebRTCSignalTransport
	// channels is the channel for negotiating new connections.
	channels *datachannel.DataChannel
	// count is the number of connections handled. It is used for
	// incrementing the connection channel ID.
	count atomic.Uint32
	// errors is a channel for receiving errors from the peer connection.
	errors chan error
	// ready is a channel for receiving a notification when the peer connection is ready.
	ready chan struct{}
	// closed is a channel for receiving a notification when the peer connection is closed.
	closed chan struct{}
	// logger is the logger to use for the connection.
	logger *slog.Logger
}

// NewPeerConnectionClient creates a new peer connection client.
func NewPeerConnectionClient(ctx context.Context, protocol string, rt transport.WebRTCSignalTransport) (*PeerConnectionClient, error) {
	// Send a request for a data channel.
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
		defer rt.Close()
		return nil, fmt.Errorf("failed to create peer connection: %w", err)
	}
	// Build the peer connection
	pc := &PeerConnectionClient{
		PeerConnection: p,
		errors:         make(chan error, 5),
		ready:          make(chan struct{}),
		closed:         make(chan struct{}),
		logger:         log,
	}
	// Create the negotiation data channel
	d, err := pc.CreateDataChannel(
		v1.DataChannel_CHANNELS.String(), &webrtc.DataChannelInit{
			Protocol:   util.Pointer("tcp"),
			Ordered:    util.Pointer(true),
			Negotiated: util.Pointer(true),
			ID:         util.Pointer(uint16(0)),
		},
	)
	if err != nil {
		defer rt.Close()
		defer pc.Close()
		return nil, fmt.Errorf("failed to create negotiation data channel: %w", err)
	}
	// Register handlers
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		err := pc.rt.SendCandidate(context.Background(), c.ToJSON())
		if err != nil {
			pc.errors <- fmt.Errorf("failed to send ICE candidate: %w", err)
		}
	})
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		pc.logger.Debug("Peer connection state has changed", "state", s.String())
		if s == webrtc.PeerConnectionStateConnected {
			defer rt.Close()
		}
		if s == webrtc.PeerConnectionStateFailed || s == webrtc.PeerConnectionStateClosed {
			defer pc.Close()
			close(pc.closed)
		}
	})
	d.OnOpen(func() {
		pc.logger.Info("Negotiation data channel opened")
		defer close(pc.ready)
		detached, err := d.Detach()
		if err != nil {
			pc.errors <- fmt.Errorf("failed to detach negotiation data channel: %w", err)
			return
		}
		pc.channels = detached.(*datachannel.DataChannel)
	})
	go pc.negotiate(rt.RemoteDescription())
	return pc, nil
}

// Errors returns a channel for receiving errors from the peer connection.
func (pc *PeerConnectionClient) Errors() <-chan error { return pc.errors }

// Ready returns a channel for receiving a notification when the peer connection is ready.
func (pc *PeerConnectionClient) Ready() <-chan struct{} { return pc.ready }

// Closed returns a channel for receiving a notification when the peer connection is closed.
func (pc *PeerConnectionClient) Closed() <-chan struct{} { return pc.closed }

// ListenAndServe creates a listener and passes incoming connections to the handler.
func (pc *PeerConnectionClient) ListenAndServe(ctx context.Context, proto, addr string) error {
	l, err := net.Listen(proto, addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	defer l.Close()
	return pc.Serve(ctx, l)
}

// Serve handles connections on the given listener.
func (pc *PeerConnectionClient) Serve(ctx context.Context, l net.Listener) error {
	errs := make(chan error, 1)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				if err == io.EOF || err == net.ErrClosed {
					return
				}
				errs <- fmt.Errorf("failed to accept connection: %w", err)
				return
			}
			go pc.Handle(conn)
		}
	}()
	select {
	case <-ctx.Done():
		return nil
	case <-pc.closed:
		return nil
	case err := <-errs:
		return err
	}
}

// Handle handles the given connection.
func (pc *PeerConnectionClient) Handle(conn net.Conn) {
	connNumber := pc.count.Add(1)
	if err := binary.Write(pc.channels, binary.BigEndian, connNumber); err != nil {
		pc.errors <- fmt.Errorf("failed to write to negotiation data channel: %w", err)
		return
	}
	d, err := pc.CreateDataChannel(
		v1.DataChannel_CONNECTIONS.String(), &webrtc.DataChannelInit{
			Protocol:   &pc.protocol,
			Ordered:    util.Pointer(true),
			Negotiated: util.Pointer(true),
			ID:         util.Pointer(uint16(connNumber)),
		})
	if err != nil {
		pc.errors <- fmt.Errorf("failed to create connection data channel: %w", err)
		return
	}
	d.OnClose(func() {
		pc.logger.Debug("Connection data channel closed:", "conn", connNumber)
	})
	d.OnOpen(func() {
		pc.logger.Debug("Connection data channel opened, proxying:", "conn", connNumber)
		defer conn.Close()
		defer d.Close()
		rw, err := d.Detach()
		if err != nil {
			pc.errors <- fmt.Errorf("failed to detach connection data channel: %w", err)
			return
		}
		go func() {
			_, err := io.Copy(rw, conn)
			if err != nil {
				pc.errors <- fmt.Errorf("failed to proxy data to data channel: %w", err)
			}
		}()
		_, err = io.Copy(conn, rw)
		if err != nil {
			pc.errors <- fmt.Errorf("failed to proxy data from data channel: %w", err)
		}
	})
}

func (pc *PeerConnectionClient) negotiate(offer webrtc.SessionDescription) {
	defer pc.rt.Close()
	// Set the remote SessionDescription
	if err := pc.SetRemoteDescription(offer); err != nil {
		pc.errors <- fmt.Errorf("failed to set remote description: %w", err)
		return
	}
	// Create and send an answer
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		pc.errors <- fmt.Errorf("failed to create answer: %w", err)
		return
	}
	if err := pc.rt.SendDescription(context.Background(), answer); err != nil {
		pc.errors <- fmt.Errorf("failed to send answer: %w", err)
		return
	}
	// Set local description and start UDP listener
	if err := pc.SetLocalDescription(answer); err != nil {
		pc.errors <- fmt.Errorf("failed to set local description: %w", err)
		return
	}
	for candidate := range pc.rt.Candidates() {
		if err := pc.AddICECandidate(candidate); err != nil {
			pc.errors <- fmt.Errorf("failed to add ICE candidate: %w", err)
			return
		}
	}
}
