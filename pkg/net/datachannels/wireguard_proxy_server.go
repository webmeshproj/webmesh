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
	"fmt"
	"log/slog"
	"sync"

	"github.com/pion/webrtc/v3"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/relay"
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

// NewWireGuardProxyServer creates a new WireGuardProxyServer using the given STUN servers
// for ICE negotiation. Traffic will be proxied to the wireguard interface listening on targetPort.
func NewWireGuardProxyServer(ctx context.Context, stunServers []string, targetPort uint16) (*WireGuardProxyServer, error) {
	s := webrtc.SettingEngine{}
	s.DetachDataChannels()
	s.SetIncludeLoopbackCandidate(true)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))
	c, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs: stunServers,
				// TODO: Authentication
				Username:       "-",
				Credential:     "-",
				CredentialType: webrtc.ICECredentialTypePassword,
			},
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
		defer mu.Unlock()
		select {
		case <-readyc:
			return
		case <-pc.closec:
			return
		case <-pc.candidatec:
			return
		default:
		}
		pc.candidatec <- c.ToJSON().Candidate
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
		}
		if state == webrtc.ICEConnectionStateFailed || state == webrtc.ICEConnectionStateCompleted {
			close(pc.candidatec)
			close(pc.closec)
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
	})
	dc.OnOpen(func() {
		log.Debug("Server side datachannel opened")
		close(pc.candidatec)
		close(readyc)
		rw, err := dc.Detach()
		if err != nil {
			log.Error("Failed to detach data channel", slog.String("error", err.Error()))
			return
		}
		relay, err := relay.NewLocalUDP(relay.UDPOptions{
			TargetPort: targetPort,
		})
		if err != nil {
			defer rw.Close()
			log.Error("Failed to create WireGuard relay", slog.String("error", err.Error()))
			return
		}
		err = relay.Relay(ctx, rw)
		if err != nil {
			log.Error("Failed to relay", slog.String("error", err.Error()))
			return
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
func (w *WireGuardProxyServer) AddCandidate(cand string) error {
	var candidate webrtc.ICECandidateInit
	err := json.Unmarshal([]byte(cand), &candidate)
	if err != nil {
		return err
	}
	return w.conn.AddICECandidate(candidate)
}

// Closed returns a channel that will be closed when the peer connection is closed.
func (w *WireGuardProxyServer) Closed() <-chan struct{} {
	return w.closec
}

// Close closes the peer connection.
func (w *WireGuardProxyServer) Close() error {
	return w.conn.Close()
}
