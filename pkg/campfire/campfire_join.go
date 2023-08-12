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

	"github.com/pion/webrtc/v3"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/services/turn"
)

// Join will attempt to join the peer waiting at the given location.
func Join(ctx context.Context, opts Options) (io.ReadWriteCloser, error) {
	log := context.LoggerFrom(ctx).With("protocol", "campfire")
	location, err := Find(opts.PSK, opts.TURNServers)
	if err != nil {
		return nil, fmt.Errorf("find campfire: %w", err)
	}
	fireconn, err := turn.NewCampfireClient(turn.CampfireClientOptions{
		Addr:  location.TURNServer,
		Ufrag: location.RemoteUfrag(),
		Pwd:   location.RemotePwd(),
		PSK:   opts.PSK,
	})
	if err != nil {
		return nil, fmt.Errorf("new campfire client: %w", err)
	}
	s := webrtc.SettingEngine{}
	s.DetachDataChannels()
	s.SetIncludeLoopbackCandidate(true)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))
	pc, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs:       []string{location.TURNServer},
				Username:   "-",
				Credential: "-",
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create peer connection: %w", err)
	}
	errs := make(chan error, 1)
	acceptc := make(chan io.ReadWriteCloser)
	dc, err := pc.CreateDataChannel(string(location.PSK), nil)
	if err != nil {
		return nil, fmt.Errorf("create data channel: %w", err)
	}
	dc.OnOpen(func() {
		log.Debug("data channel open")
		rw, err := dc.Detach()
		if err != nil {
			errs <- fmt.Errorf("detach data channel: %w", err)
			return
		}
		acceptc <- rw
	})
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return nil, fmt.Errorf("create offer: %w", err)
	}
	err = pc.SetLocalDescription(offer)
	if err != nil {
		return nil, fmt.Errorf("set local description: %w", err)
	}
	err = fireconn.SendOffer(location.LocalUfrag(), location.LocalPwd(), offer)
	if err != nil {
		return nil, fmt.Errorf("send offer: %w", err)
	}
	connectedc := make(chan struct{})
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		select {
		case <-connectedc:
			return
		default:
		}
		log.Debug("sending local ICE candidate", "candidate", c.String())
		err = fireconn.SendCandidate(location.LocalUfrag(), location.LocalPwd(), c)
		if err != nil {
			errs <- fmt.Errorf("send ice candidate: %w", err)
			return
		}
	})
	var answer turn.CampfireAnswer
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case answer = <-fireconn.Answers():
	}
	log.Debug("received answer", "answer", answer.SDP)
	err = pc.SetRemoteDescription(answer.SDP)
	if err != nil {
		return nil, fmt.Errorf("set remote description: %w", err)
	}
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		log.Debug("peer connection state change", "state", state.String())
		if state == webrtc.PeerConnectionStateConnected {
			close(connectedc)
		}
		if state == webrtc.PeerConnectionStateDisconnected || state == webrtc.PeerConnectionStateFailed {
			errs <- fmt.Errorf("peer connection state: %s", state.String())
		}
	})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-connectedc:
				return
			case cand := <-fireconn.Candidates():
				log.Debug("received remote ICE candidate", "candidate", cand.Cand)
				err = pc.AddICECandidate(cand.Cand)
				if err != nil {
					errs <- fmt.Errorf("add ice candidate: %w", err)
					return
				}
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-fireconn.Errors():
		return nil, err
	case err := <-errs:
		return nil, err
	case rw := <-acceptc:
		return rw, nil
	}
}
