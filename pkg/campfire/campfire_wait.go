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

package campfire

import (
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/pion/webrtc/v3"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/services/turn"
)

// Wait will wait for peers to join at the given location.
func Wait(ctx context.Context, camp *CampfireURI) (CampfireChannel, error) {
	log := context.LoggerFrom(ctx).With("protocol", "campfire")
	location, err := Find(camp.PSK, camp.TURNServers)
	if err != nil {
		return nil, fmt.Errorf("find campfire: %w", err)
	}
	log.Debug("Found campfire location", "location", location.TURNServer)
	fireconn, err := turn.NewCampfireClient(turn.CampfireClientOptions{
		Addr:  location.TURNServer,
		Ufrag: location.LocalUfrag(),
		Pwd:   location.LocalPwd(),
		PSK:   camp.PSK,
	})
	if err != nil {
		return nil, fmt.Errorf("new campfire client: %w", err)
	}
	err = fireconn.Announce(location.RemoteUfrag(), location.RemotePwd())
	if err != nil {
		return nil, fmt.Errorf("announce: %w", err)
	}
	log.Debug("Announced campfire location", "location", location.TURNServer)
	s := webrtc.SettingEngine{}
	s.DetachDataChannels()
	s.SetIncludeLoopbackCandidate(true)
	tw := &turnWait{
		api:        webrtc.NewAPI(webrtc.WithSettingEngine(s)),
		location:   location,
		fireconn:   fireconn,
		acceptc:    make(chan io.ReadWriteCloser, 1),
		closec:     make(chan struct{}),
		errc:       make(chan error, 10),
		inProgress: make(map[string]*webrtc.PeerConnection),
		log:        log,
	}
	go tw.handleIncomingOffers()
	go tw.handleIncomingCandidates()
	return tw, nil
}

type turnWait struct {
	api        *webrtc.API
	location   *Location
	fireconn   *turn.CampfireClient
	acceptc    chan io.ReadWriteCloser
	closec     chan struct{}
	errc       chan error
	inProgress map[string]*webrtc.PeerConnection
	log        *slog.Logger
	mu         sync.Mutex
}

// Accept returns a connection to a peer.
func (t *turnWait) Accept() (io.ReadWriteCloser, error) {
	select {
	case <-t.closec:
		return nil, ErrClosed
	case conn := <-t.acceptc:
		return conn, nil
	}
}

// Close closes the camp fire.
func (t *turnWait) Close() error {
	close(t.closec)
	return t.fireconn.Close()
}

// Opened returns true if the camp fire is opened.
func (t *turnWait) Opened() bool {
	select {
	case <-t.closec:
		return false
	default:
		return true
	}
}

// Errors returns a channel of errors.
func (t *turnWait) Errors() <-chan error { return t.errc }

// Expired returns a channel that is closed when the camp fire expires.
func (t *turnWait) Expired() <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		select {
		case <-t.closec:
		case <-time.After(time.Until(t.location.ExpiresAt)):
		}
	}()
	return ch
}

func (t *turnWait) handleIncomingOffers() {
	offers := t.fireconn.Offers()
	for {
		select {
		case <-t.closec:
			return
		case err := <-t.fireconn.Errors():
			t.errc <- fmt.Errorf("campfire client: %w", err)
		case offer := <-offers:
			if offer.Ufrag != t.location.RemoteUfrag() || offer.Pwd != t.location.RemotePwd() {
				t.log.Warn("received offer with unexpected ufrag/pwd", "ufrag", offer.Ufrag, "pwd", offer.Pwd)
				continue
			}
			go t.handleNewPeerConnection(&offer)
		}
	}
}

func (t *turnWait) handleIncomingCandidates() {
	candidates := t.fireconn.Candidates()
	for {
		select {
		case <-t.closec:
			return
		case cand := <-candidates:
			t.mu.Lock()
			conn, ok := t.inProgress[cand.ID]
			if !ok {
				t.log.Warn("Received candidate for unknown connection", "id", cand.ID)
				t.mu.Unlock()
				continue
			}
			t.log.Debug("Received remote ice candidate", "candidate", cand)
			err := conn.AddICECandidate(cand.Cand)
			if err != nil {
				t.log.Error("Error adding ice candidate", "error", err)
			}
			t.mu.Unlock()
		}
	}
}

func (t *turnWait) handleNewPeerConnection(offer *turn.CampfireOffer) {
	t.mu.Lock()
	t.log.Debug("Creating new peer connection", "offer", offer)
	pc, err := t.api.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs:       []string{t.location.TURNServer},
				Username:   "-",
				Credential: "-",
			},
		},
	})
	if err != nil {
		t.mu.Unlock()
		t.errc <- fmt.Errorf("new peer connection: %w", err)
		return
	}
	t.inProgress[offer.ID] = pc
	t.mu.Unlock()
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		t.log.Debug("Sending local ice candidate", "candidate", c)
		err := t.fireconn.SendCandidate(offer.ID, t.location.RemoteUfrag(), t.location.RemotePwd(), c)
		if err != nil {
			t.log.Warn("failed to send ice candidate", "err", err)
		}
	})
	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		t.log.Debug("ICE connection state changed", "state", state)
		if state == webrtc.ICEConnectionStateConnected || state == webrtc.ICEConnectionStateCompleted {
			t.mu.Lock()
			delete(t.inProgress, offer.ID)
			t.mu.Unlock()
		}
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		t.log.Debug("Received data channel", "label", dc.Label())
		if dc.Label() != string(t.location.PSK) {
			t.log.Warn("received data channel with unexpected label", "label", dc.Label())
			return
		}
		dc.OnOpen(func() {
			rw, err := dc.Detach()
			if err != nil {
				t.errc <- fmt.Errorf("detach data channel: %w", err)
				return
			}
			t.acceptc <- rw
		})
	})
	err = pc.SetRemoteDescription(offer.SDP)
	if err != nil {
		t.errc <- fmt.Errorf("set remote description: %w", err)
		return
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		t.errc <- fmt.Errorf("create answer: %w", err)
		return
	}
	err = pc.SetLocalDescription(answer)
	if err != nil {
		t.errc <- fmt.Errorf("set local description: %w", err)
		return
	}
	t.log.Debug("Sending answer", "answer", answer)
	err = t.fireconn.SendAnswer(offer.ID, t.location.RemoteUfrag(), t.location.RemotePwd(), answer)
	if err != nil {
		t.errc <- fmt.Errorf("send answer: %w", err)
		return
	}
}
