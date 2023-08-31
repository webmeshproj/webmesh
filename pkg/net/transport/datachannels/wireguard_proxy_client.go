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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/pion/webrtc/v3"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/util"
)

// WireGuardProxyClient is a WireGuard proxy client. It is used for outgoing
// requests to establish a WireGuard proxy connection.
type WireGuardProxyClient struct {
	conn       *webrtc.PeerConnection
	localAddr  *net.UDPAddr
	readyc     chan struct{}
	closec     chan struct{}
	bufferSize int
}

// NewWireGuardProxyClient creates a new WireGuardProxyClient using the given signaling transport.
// Traffic will be proxied to the wireguard interface listening on targetPort. It contains a method
// for retrieving the local address to use as a WireGuard endpoint for the peer on the other side of
// the proxy.
func NewWireGuardProxyClient(ctx context.Context, rt transport.WebRTCSignalTransport, targetPort uint16) (*WireGuardProxyClient, error) {
	log := context.LoggerFrom(ctx)
	log.Debug("Starting signaling transport")
	err := rt.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start signaling transport: %w", err)
	}
	defer rt.Close()
	s := webrtc.SettingEngine{}
	s.DetachDataChannels()
	s.SetIncludeLoopbackCandidate(true)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))
	c, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: rt.TURNServers(),
	})
	if err != nil {
		defer rt.Close()
		return nil, fmt.Errorf("failed to create peer connection: %w", err)
	}
	pc := &WireGuardProxyClient{
		conn:       c,
		readyc:     make(chan struct{}),
		closec:     make(chan struct{}),
		bufferSize: DefaultWireGuardProxyBuffer,
	}
	errs := make(chan error, 10)
	pc.conn.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		log.Debug("Sending ICE candidate", "candidate", c.ToJSON().Candidate)
		err := rt.SendCandidate(ctx, c.ToJSON())
		if err != nil {
			if transport.IsSignalTransportClosed(err) {
				return
			}
			defer rt.Close()
			errs <- fmt.Errorf("failed to send ICE candidate: %w", err)
		}
	})
	pc.conn.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) {
		log.Debug("ICE connection state changed", "state", s.String())
		if s == webrtc.ICEConnectionStateConnected {
			close(pc.readyc)
			candidatePair, err := pc.conn.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
			if err != nil {
				log.Error("Failed to get selected candidate pair", slog.String("error", err.Error()))
				return
			}
			log.Debug("ICE connection established", slog.Any("local", candidatePair.Local), slog.Any("remote", candidatePair.Remote))
			return
		}
		if s == webrtc.ICEConnectionStateFailed || s == webrtc.ICEConnectionStateClosed {
			log.Info("ICE connection has closed", "reason", s.String())
			defer pc.Close()
			close(pc.closec)
		}
	})
	dc, err := pc.conn.CreateDataChannel("wireguard-proxy", &webrtc.DataChannelInit{
		ID:         util.Pointer(uint16(0)),
		Negotiated: util.Pointer(true),
	})
	if err != nil {
		defer pc.Close()
		return nil, fmt.Errorf("create data channel: %w", err)
	}
	wgiface, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: int(targetPort),
	})
	if err != nil {
		defer pc.Close()
		return nil, fmt.Errorf("dial: %w", err)
	}
	pc.localAddr = wgiface.LocalAddr().(*net.UDPAddr)
	dc.OnClose(func() {
		log.Debug("Client side WireGuard datachannel closed")
	})
	dc.OnOpen(func() {
		log.Debug("Client side datachannel opened")
		var err error
		rw, err := dc.Detach()
		if err != nil {
			log.Error("Failed to detach data channel", slog.String("error", err.Error()))
			return
		}
		log.Debug("WireGuard proxy from local to datachannel started")
		go func() {
			defer log.Debug("WireGuard proxy from local to datachannel stopped")
			defer wgiface.Close()
			_, err := io.CopyBuffer(rw, wgiface, make([]byte, pc.bufferSize))
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
					return
				}
				log.Error("Failed to copy from WireGuard to datachannel", slog.String("error", err.Error()))
			}
		}()
		log.Debug("WireGuard proxy from datachannel to local started")
		defer log.Debug("WireGuard proxy from datachannel to local stopped")
		defer pc.Close()
		_, err = io.CopyBuffer(wgiface, rw, make([]byte, pc.bufferSize))
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Error("Failed to copy from datachannel to WireGuard", slog.String("error", err.Error()))
		}
	})
	var offer webrtc.SessionDescription
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("context canceled")
	case err := <-rt.Error():
		return nil, fmt.Errorf("signaling transport error: %w", err)
	case offer = <-rt.Descriptions():
	}
	err = pc.conn.SetRemoteDescription(offer)
	if err != nil {
		defer pc.Close()
		return nil, fmt.Errorf("failed to set remote description: %w", err)
	}
	// Create and send an answer
	answer, err := pc.conn.CreateAnswer(nil)
	if err != nil {
		defer pc.Close()
		return nil, fmt.Errorf("failed to create answer: %w", err)
	}
	err = rt.SendDescription(ctx, answer)
	if err != nil {
		defer pc.Close()
		return nil, fmt.Errorf("failed to send answer: %w", err)
	}
	// Set local description and start UDP listener
	err = pc.conn.SetLocalDescription(answer)
	if err != nil {
		defer pc.Close()
		return nil, fmt.Errorf("failed to set local description: %w", err)
	}
	// Receive ICE candidates
	go func() {
		for candidate := range rt.Candidates() {
			log.Debug("Received ICE candidate", "candidate", candidate.Candidate)
			if err := pc.conn.AddICECandidate(candidate); err != nil {
				errs <- fmt.Errorf("failed to add ICE candidate: %w", err)
			}
		}
	}()
	select {
	case err := <-errs:
		return nil, err
	case <-time.After(15 * time.Second):
		return nil, fmt.Errorf("timed out waiting for data channel to open")
	case <-pc.readyc:
	}
	return pc, nil
}

// LocalAddr returns the local UDP address for the proxy. This should be
// used as the endpoint for the WireGuard interface.
func (w *WireGuardProxyClient) LocalAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: w.localAddr.Port,
	}
}

// Closed returns a channel that is closed when the proxy is closed.
func (w *WireGuardProxyClient) Closed() <-chan struct{} {
	return w.closec
}

// Close closes the proxy.
func (w *WireGuardProxyClient) Close() error {
	return w.conn.Close()
}
