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
	"bytes"
	"crypto"
	"fmt"
	"io"
	"net"
	"strings"
	"text/template"

	"github.com/pion/datachannel"
	"github.com/pion/dtls/v2/pkg/crypto/fingerprint"
	"github.com/pion/ice/v2"
	"github.com/pion/webrtc/v3"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// Join will attempt to join the peer waiting at the given location.
func Join(ctx context.Context, opts Options) (io.ReadWriteCloser, error) {
	log := context.LoggerFrom(ctx).With("protocol", "campfire")
	_, cert, err := loadCertificate()
	if err != nil {
		return nil, fmt.Errorf("load certificate: %w", err)
	}
	location, err := Find(opts.PSK, opts.TURNServers)
	if err != nil {
		return nil, fmt.Errorf("find campfire: %w", err)
	}
	turnHost, err := net.ResolveUDPAddr("udp", strings.TrimPrefix(location.TURNServer, "turn:"))
	if err != nil {
		return nil, fmt.Errorf("resolve turn server: %w", err)
	}
	s := webrtc.SettingEngine{}
	s.DetachDataChannels()
	s.SetICECredentials(location.LocalUfrag(), location.LocalPwd())
	s.SetIncludeLoopbackCandidate(true)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))
	pc, err := api.NewPeerConnection(webrtc.Configuration{
		ICETransportPolicy: webrtc.ICETransportPolicyRelay,
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
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		log.Debug("ICE candidate", "candidate", c.String())
	})
	pc.OnNegotiationNeeded(func() {
		offer, err := pc.CreateOffer(nil)
		if err != nil {
			errs <- fmt.Errorf("create offer: %w", err)
			return
		}
		err = pc.SetLocalDescription(offer)
		if err != nil {
			errs <- fmt.Errorf("set local description: %w", err)
			return
		}
		fingerprint, err := fingerprint.Fingerprint(cert, crypto.SHA256)
		if err != nil {
			errs <- fmt.Errorf("fingerprint certificate: %w", err)
			return
		}
		var answer bytes.Buffer
		err = joinerRemoteTemplate.Execute(&answer, map[string]any{
			"SessionID":   location.SessionID(),
			"Username":    location.RemoteUfrag(),
			"Secret":      location.RemotePwd(),
			"Fingerprint": strings.ToUpper(fingerprint),
			"TURNServer":  turnHost.AddrPort().Addr().String(),
			"TURNPort":    turnHost.Port,
		})
		if err != nil {
			errs <- fmt.Errorf("execute remote template: %w", err)
			return
		}
		err = pc.SetRemoteDescription(webrtc.SessionDescription{
			Type: webrtc.SDPTypeAnswer,
			SDP:  answer.String(),
		})
		if err != nil {
			errs <- fmt.Errorf("set remote description: %w", err)
			return
		}
		turnCandidate, err := ice.NewCandidateRelay(&ice.CandidateRelayConfig{
			Network: "udp",
			Address: turnHost.AddrPort().Addr().String(),
			Port:    turnHost.Port,
		})
		if err != nil {
			errs <- fmt.Errorf("new turn candidate: %w", err)
			return
		}
		err = pc.AddICECandidate(webrtc.ICECandidateInit{
			Candidate: turnCandidate.Marshal(),
		})
		if err != nil {
			errs <- fmt.Errorf("add turn candidate: %w", err)
			return
		}
	})
	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		log.Debug("ICE connection state changed", "state", state.String())
		switch state {
		case webrtc.ICEConnectionStateFailed:
			errs <- fmt.Errorf("ice connection failed")
		}
	})
	dc, err := pc.CreateDataChannel("webrtc-datachannel", nil)
	if err != nil {
		return nil, fmt.Errorf("create data channel: %w", err)
	}
	acceptc := make(chan datachannel.ReadWriteCloser, 1)
	dc.OnOpen(func() {
		log.Info("data channel opened")
		rw, err := dc.Detach()
		if err != nil {
			errs <- fmt.Errorf("detach data channel: %w", err)
			return
		}
		acceptc <- campfireConn{ReadWriteCloser: rw, pc: pc}
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errs:
		return nil, err
	case rw := <-acceptc:
		return rw, nil
	}
}

type campfireConn struct {
	datachannel.ReadWriteCloser
	pc *webrtc.PeerConnection
}

var joinerRemoteTemplate = template.Must(template.New("cli-remote-desc").Parse(`v=0
o=- {{ .SessionID }} 2 IN IP4 0.0.0.0
s=-
t=0 0
a=fingerprint:sha-256 {{ .Fingerprint }}
a=group:BUNDLE 0
a=ice-lite
m=application 9 DTLS/SCTP 5000
c=IN IP4 0.0.0.0
a=setup:active
a=mid:0
a=sendrecv
a=sctpmap:5000 webrtc-datachannel 1024
a=ice-ufrag:{{ .Username }}
a=ice-pwd:{{ .Secret }}
a=candidate:1 1 UDP 99999 {{ .TURNServer }} {{ .TURNPort }} typ relay 127.0.0.1 50000
`))
