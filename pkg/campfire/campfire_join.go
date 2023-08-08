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

// Package campfire implements the "camp fire" protocol.
package campfire

import (
	"fmt"
	"io"

	"github.com/pion/datachannel"
	"github.com/pion/webrtc/v3"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/util"
)

// CampFire is a connection to one or more peers sharing the same pre-shared
// key.
type CampFire struct {
	room    WaitingRoom
	errc    chan error
	readyc  chan struct{}
	acceptc chan datachannel.ReadWriteCloser
	closec  chan struct{}
	log     *slog.Logger
}

// Options are options for creating or joining a new camp fire.
type Options struct {
	// PSK is the pre-shared key.
	PSK []byte
	// TURNServers is an optional list of turn servers to use.
	TURNServers []string
}

// Join joins a camp fire with the given pre-shared key on the list of turn
// servers.
func Join(ctx context.Context, room WaitingRoom) *CampFire {
	cf := CampFire{
		errc:    make(chan error, 3),
		readyc:  make(chan struct{}),
		acceptc: make(chan datachannel.ReadWriteCloser, 1),
		closec:  make(chan struct{}),
	}
	cf.log = context.LoggerFrom(ctx).With("protocol", "campfire")
	cf.room = room
	go func() {
		for {
			select {
			case <-cf.closec:
				return
			case err := <-cf.room.Errors():
				cf.errc <- fmt.Errorf("waiting room error: %w", err)
			case peerconn := <-cf.room.Peers():
				go cf.onNewPeerConnection(ctx, peerconn)
			case srvconn := <-cf.room.Connections():
				go cf.onNewIncomingStream(ctx, srvconn)
			}
		}
	}()
	return &cf
}

func (cf *CampFire) Accept() (datachannel.ReadWriteCloser, error) {
	select {
	case <-cf.closec:
		return nil, fmt.Errorf("camp fire closed")
	case <-cf.readyc:
		return <-cf.acceptc, nil
	}
}

func (cf *CampFire) Close() error {
	close(cf.closec)
	return cf.room.Close()
}

func (cf *CampFire) Errors() <-chan error {
	return cf.errc
}

func (cf *CampFire) Ready() <-chan struct{} {
	return cf.readyc
}

func (cf *CampFire) onNewPeerConnection(ctx context.Context, stream Stream) {
	s := webrtc.SettingEngine{}
	s.DetachDataChannels()
	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))
	loc := cf.room.Location()
	conn, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs:           []string{loc.TURNServer},
				Username:       "-",
				Credential:     loc.Secret,
				CredentialType: webrtc.ICECredentialTypePassword,
			},
		},
		PeerIdentity: loc.Secret,
		// ICETransportPolicy: webrtc.ICETransportPolicyRelay,
	})
	if err != nil {
		cf.errc <- fmt.Errorf("new peer connection: %w", err)
		return
	}
	conn.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		cf.log.Debug("ICE connection state changed", "state", state.String())
		switch state {
		case webrtc.ICEConnectionStateConnected:
			defer stream.Close()
			close(cf.readyc)
		case webrtc.ICEConnectionStateFailed:
			cf.errc <- fmt.Errorf("ice connection failed")
		}
	})
	conn.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		select {
		case <-cf.readyc:
		default:
			cf.log.Debug("got local ice candidate", "candidate", c.ToJSON().Candidate)
			candidate := c.ToJSON().Candidate
			err := stream.SendCandidate(candidate)
			if err != nil {
				cf.log.Error("send error", "error", err.Error())
				cf.errc <- fmt.Errorf("send ice candidate: %w", err)
			}
		}
	})
	dc, err := conn.CreateDataChannel(cf.room.Location().Secret, &webrtc.DataChannelInit{
		ID:         util.Pointer(uint16(0)),
		Ordered:    util.Pointer(true),
		Negotiated: util.Pointer(true),
		Protocol:   util.Pointer("campfire"),
	})
	if err != nil {
		cf.errc <- fmt.Errorf("create data channel: %w", err)
		return
	}
	dc.OnOpen(func() {
		cf.log.Debug("data channel has opened")
		candidatePair, err := conn.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
		if err == nil {
			cf.log.Debug("selected candidate pair", "local", candidatePair.Local.String(), "remote", candidatePair.Remote.String())
		}
		dt, err := dc.Detach()
		if err != nil {
			cf.errc <- fmt.Errorf("detach data channel: %w", err)
			return
		}
		cf.acceptc <- dt
	})
	cf.log.Debug("creating offer to send to peer")
	offer, err := conn.CreateOffer(nil)
	if err != nil {
		cf.errc <- fmt.Errorf("create offer: %w", err)
		return
	}
	err = conn.SetLocalDescription(offer)
	if err != nil {
		cf.errc <- fmt.Errorf("set local description: %w", err)
		return
	}
	err = stream.SendOffer(offer)
	if err != nil {
		cf.errc <- fmt.Errorf("send offer: %w", err)
		return
	}
	cf.log.Debug("wrote offer to peer")
	// Handle negotiation
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				if err == io.EOF {
					return
				}
				cf.errc <- fmt.Errorf("receive message: %w", err)
				return
			}
			switch msg.Type {
			case SDPMessageType:
				answer, err := msg.UnmarshalSDP()
				if err != nil {
					cf.errc <- fmt.Errorf("unmarshal answer: %w", err)
					return
				}
				err = conn.SetRemoteDescription(answer)
				if err != nil {
					cf.errc <- fmt.Errorf("set remote description: %w", err)
					return
				}
			case CandidateMessageType:
				/// Add the remote ICE candidate
				candidate := webrtc.ICECandidateInit{
					Candidate: msg.Candidate,
				}
				err = conn.AddICECandidate(candidate)
				if err != nil {
					cf.errc <- fmt.Errorf("add ice candidate: %w", err)
					return
				}
			}
		}
	}()
}

func (cf *CampFire) onNewIncomingStream(ctx context.Context, stream Stream) {
	cf.log.Info("new incoming stream", "peer", stream.PeerID())
	s := webrtc.SettingEngine{}
	s.DetachDataChannels()
	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))
	loc := cf.room.Location()
	conn, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs:           []string{loc.TURNServer},
				Username:       "-",
				Credential:     loc.Secret,
				CredentialType: webrtc.ICECredentialTypePassword,
			},
		},
		PeerIdentity: loc.Secret,
		// ICETransportPolicy: webrtc.ICETransportPolicyRelay,
	})
	if err != nil {
		cf.errc <- fmt.Errorf("new peer connection: %w", err)
		return
	}
	conn.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		cf.log.Debug("ICE connection state changed", "state", state.String())
		switch state {
		case webrtc.ICEConnectionStateConnected:
			defer stream.Close()
			close(cf.readyc)
		case webrtc.ICEConnectionStateFailed:
			cf.errc <- fmt.Errorf("ice connection failed")
		}
	})
	conn.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		cf.log.Debug("got local ice candidate", "candidate", c.ToJSON().Candidate)
		select {
		case <-cf.readyc:
		default:
			cf.log.Debug("got local ice candidate", "candidate", c.ToJSON().Candidate)
			candidate := c.ToJSON().Candidate
			err := stream.SendCandidate(candidate)
			if err != nil {
				cf.log.Error("send error", "error", err.Error())
				cf.errc <- fmt.Errorf("send ice candidate: %w", err)
			}
		}
	})
	dc, err := conn.CreateDataChannel(loc.Secret, &webrtc.DataChannelInit{
		ID:         util.Pointer(uint16(0)),
		Ordered:    util.Pointer(true),
		Negotiated: util.Pointer(true),
		Protocol:   util.Pointer("campfire"),
	})
	if err != nil {
		cf.errc <- fmt.Errorf("create data channel: %w", err)
		return
	}
	dc.OnOpen(func() {
		cf.log.Debug("data channel has opened")
		candidatePair, err := conn.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
		if err == nil {
			cf.log.Debug("selected candidate pair", "local", candidatePair.Local.String(), "remote", candidatePair.Remote.String())
		}
		dt, err := dc.Detach()
		if err != nil {
			cf.errc <- fmt.Errorf("detach data channel: %w", err)
			return
		}
		cf.acceptc <- dt
	})
	// Handle negotiation
	go func() {
		for {
			msg, err := stream.Receive()
			if err != nil {
				if err == io.EOF {
					return
				}
				cf.errc <- fmt.Errorf("receive message: %w", err)
				return
			}
			switch msg.Type {
			case SDPMessageType:
				offer, err := msg.UnmarshalSDP()
				if err != nil {
					cf.errc <- fmt.Errorf("unmarshal offer: %w", err)
					return
				}
				err = conn.SetRemoteDescription(offer)
				if err != nil {
					cf.errc <- fmt.Errorf("set remote description: %w", err)
					return
				}
				// Create an answer
				answer, err := conn.CreateAnswer(nil)
				if err != nil {
					cf.errc <- fmt.Errorf("create answer: %w", err)
					return
				}
				err = conn.SetLocalDescription(answer)
				if err != nil {
					cf.errc <- fmt.Errorf("set local description: %w", err)
					return
				}
				err = stream.SendOffer(answer)
				if err != nil {
					cf.errc <- fmt.Errorf("send answer: %w", err)
					return
				}
			case CandidateMessageType:
				/// Add the remote ICE candidate
				cf.log.Debug("got remote ice candidate", "candidate", msg.Candidate)
				candidate := webrtc.ICECandidateInit{
					Candidate: msg.Candidate,
				}
				err = conn.AddICECandidate(candidate)
				if err != nil {
					cf.errc <- fmt.Errorf("add ice candidate: %w", err)
					return
				}
			}
		}
	}()
}
