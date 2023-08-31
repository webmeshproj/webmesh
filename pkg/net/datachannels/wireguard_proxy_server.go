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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/pion/webrtc/v3"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/util"
)

// WireguardProxyServer is a WebRTC datachannel proxy for WireGuard. It is used
// for incoming requests to proxy traffic to a WireGuard interface.
type WireGuardProxyServer struct {
	conn       *webrtc.PeerConnection
	candidatec chan string
	messages   chan []byte
	closec     chan struct{}
	offer      []byte
	bufferSize int
}

// NewWireGuardProxyServer creates a new WireGuardProxyServer using the given STUN servers.
// Traffix will be proxied to the wireguard interface listening on targetPort.
func NewWireGuardProxyServer(ctx context.Context, stunServers []string, targetPort uint16) (*WireGuardProxyServer, error) {
	s := webrtc.SettingEngine{}
	s.DetachDataChannels()
	s.SetIncludeLoopbackCandidate(true)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))
	c, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{URLs: stunServers},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("new peer connection: %w", err)
	}
	pc := &WireGuardProxyServer{
		conn:       c,
		candidatec: make(chan string, 10),
		messages:   make(chan []byte, 10),
		closec:     make(chan struct{}),
		bufferSize: DefaultWireGuardProxyBuffer,
	}
	log := context.LoggerFrom(ctx)
	readyc := make(chan struct{})
	var mu sync.Mutex
	pc.conn.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		log.Debug("Received ICE candidate", slog.Any("candidate", c))
		mu.Lock()
		select {
		case <-readyc:
			return
		case <-pc.closec:
		default:
		}
		pc.candidatec <- c.ToJSON().Candidate
		mu.Unlock()
	})
	pc.conn.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		mu.Lock()
		defer mu.Unlock()
		log.Debug("ICE connection state changed", slog.String("state", state.String()))
		if state == webrtc.ICEConnectionStateConnected {
			candidatePair, err := pc.conn.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
			if err != nil {
				log.Error("Failed to get selected candidate pair", slog.String("error", err.Error()))
				return
			}
			log.Debug("ICE connection established", slog.Any("local", candidatePair.Local), slog.Any("remote", candidatePair.Remote))
			close(readyc)
		}
		if state == webrtc.ICEConnectionStateFailed || state == webrtc.ICEConnectionStateClosed || state == webrtc.ICEConnectionStateCompleted {
			select {
			case <-pc.closec:
			default:
				close(pc.closec)
			}
		}
	})
	dc, err := pc.conn.CreateDataChannel("wireguard-proxy", &webrtc.DataChannelInit{
		ID:         util.Pointer(uint16(0)),
		Negotiated: util.Pointer(true),
	})
	if err != nil {
		return nil, fmt.Errorf("create data channel: %w", err)
	}
	dc.OnClose(func() {
		log.Debug("Server side WireGuard datachannel closed")
		close(pc.closec)
	})
	dc.OnOpen(func() {
		log.Debug("Server side datachannel opened")
		close(pc.candidatec)
		rw, err := dc.Detach()
		if err != nil {
			log.Error("Failed to detach data channel", slog.String("error", err.Error()))
			return
		}
		wgiface, err := net.DialUDP("udp", nil, &net.UDPAddr{
			IP:   net.IPv4zero,
			Port: int(targetPort),
		})
		if err != nil {
			defer rw.Close()
			log.Error("Failed to dial UDP", slog.String("error", err.Error()))
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
		defer pc.conn.Close()
		_, err = io.CopyBuffer(wgiface, rw, make([]byte, pc.bufferSize))
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Error("Failed to copy from datachannel to WireGuard", slog.String("error", err.Error()))
		}
	})
	offer, err := pc.conn.CreateOffer(nil)
	if err != nil {
		return nil, fmt.Errorf("create offer: %w", err)
	}
	err = pc.conn.SetLocalDescription(offer)
	if err != nil {
		return nil, fmt.Errorf("set local description: %w", err)
	}
	pc.offer, err = json.Marshal(offer)
	if err != nil {
		return nil, fmt.Errorf("marshal offer: %w", err)
	}
	return pc, nil
}

// Offer returns the offer to be sent to the peer.
func (w *WireGuardProxyServer) Offer() string {
	return string(w.offer)
}

// AnswerOffer sets the answer to the offer returned by the peer.
func (w *WireGuardProxyServer) AnswerOffer(answer string) error {
	var answerInit webrtc.SessionDescription
	err := json.Unmarshal([]byte(answer), &answerInit)
	if err != nil {
		return err
	}
	return w.conn.SetRemoteDescription(answerInit)
}

// Candidates returns a channel that will receive potential ICE candidates to be sent to the peer.
func (w *WireGuardProxyServer) Candidates() <-chan string {
	return w.candidatec
}

// AddCandidate adds an ICE candidate to the peer connection.
func (w *WireGuardProxyServer) AddCandidate(candidate string) error {
	return w.conn.AddICECandidate(webrtc.ICECandidateInit{
		Candidate: candidate,
	})
}

// Closed returns a channel that will be closed when the peer connection is closed.
func (w *WireGuardProxyServer) Closed() <-chan struct{} {
	return w.closec
}

// Close closes the peer connection.
func (w *WireGuardProxyServer) Close() error {
	return w.conn.Close()
}
