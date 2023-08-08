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
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"text/template"

	"github.com/pion/datachannel"
	"github.com/pion/webrtc/v3"

	"github.com/webmeshproj/webmesh/pkg/context"
)

type offlineCampFire struct {
	api     *webrtc.API
	certs   []webrtc.Certificate
	loc     *Location
	errc    chan error
	readyc  chan struct{}
	acceptc chan datachannel.ReadWriteCloser
	closec  chan struct{}
	log     *slog.Logger
}

var (
	// CampfireUFrag is the username fragment used by campfire.
	CampfireUFrag = base64.StdEncoding.EncodeToString([]byte("campfire"))

	//go:embed zcampfire.crt
	campfireCert []byte
	//go:embed zcampfire.key
	campfireKey []byte
)

// Wait waits for a peer to join the camp fire and dispatches a connections
// and errors to the appropriate channels.
func Wait(ctx context.Context, opts Options) (CampFire, error) {
	certs, _, err := loadCertificate()
	if err != nil {
		return nil, fmt.Errorf("load certificate: %w", err)
	}
	loc, err := Find(opts.PSK, opts.TURNServers)
	if err != nil {
		return nil, fmt.Errorf("find campfire: %w", err)
	}
	s := webrtc.SettingEngine{}
	s.DetachDataChannels()
	s.DisableCertificateFingerprintVerification(true)
	s.SetICECredentials(CampfireUFrag, loc.Secret)
	cf := offlineCampFire{
		api:     webrtc.NewAPI(webrtc.WithSettingEngine(s)),
		certs:   certs,
		loc:     loc,
		errc:    make(chan error, 3),
		readyc:  make(chan struct{}),
		acceptc: make(chan datachannel.ReadWriteCloser, 1),
		closec:  make(chan struct{}),
		log:     context.LoggerFrom(ctx).With("protocol", "campfire"),
	}
	go cf.handlePeerConnections()
	return &cf, nil
}

func (o *offlineCampFire) handlePeerConnections() {
	defer close(o.readyc)
	var remoteDescription bytes.Buffer
	err := waiterRemoteTemplate.Execute(&remoteDescription, map[string]string{
		"Username": CampfireUFrag,
		"Secret":   o.loc.Secret,
	})
	if err != nil {
		o.errc <- fmt.Errorf("execute remote template: %w", err)
		return
	}
	pc, err := o.api.NewPeerConnection(webrtc.Configuration{
		Certificates: o.certs,
		ICEServers: []webrtc.ICEServer{
			{
				URLs:       []string{strings.Replace(o.loc.TURNServer, "turn", "stun", 1)},
				Username:   "-",
				Credential: "-",
			},
		},
	})
	if err != nil {
		o.errc <- fmt.Errorf("new peer connection: %w", err)
		return
	}
	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		o.log.Debug("ICE connection state changed", "state", state.String())
		switch state {
		case webrtc.ICEConnectionStateConnected:
			close(o.readyc)
		case webrtc.ICEConnectionStateFailed:
			o.errc <- fmt.Errorf("ice connection failed")
		}
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		o.log.Debug("Data channel opened", "label", dc.Label())
		if dc.Label() != o.loc.Secret {
			o.errc <- fmt.Errorf("unexpected data channel label: %q", dc.Label())
			return
		}
		rw, err := dc.Detach()
		if err != nil {
			o.errc <- fmt.Errorf("detach data channel: %w", err)
			return
		}
		o.acceptc <- rw
	})
	err = pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  remoteDescription.String(),
	})
	if err != nil {
		o.errc <- fmt.Errorf("set remote description: %w", err)
		return
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		o.errc <- fmt.Errorf("create answer: %w", err)
		return
	}
	err = pc.SetLocalDescription(answer)
	if err != nil {
		o.errc <- fmt.Errorf("set local description: %w", err)
		return
	}
}

// Accept returns a connection to a peer.
func (o *offlineCampFire) Accept() (datachannel.ReadWriteCloser, error) {
	select {
	case <-o.closec:
		return nil, ErrClosed
	case <-o.readyc:
	}
	select {
	case <-o.closec:
		return nil, ErrClosed
	case conn := <-o.acceptc:
		return conn, nil
	}
}

// Close closes the camp fire.
func (o *offlineCampFire) Close() error {
	select {
	case <-o.closec:
		return ErrClosed
	default:
		close(o.closec)
	}
	return nil
}

// Errors returns a channel of errors.
func (o *offlineCampFire) Errors() <-chan error {
	return o.errc
}

// Ready returns a channel that is closed when the camp fire is ready.
func (o *offlineCampFire) Ready() <-chan struct{} {
	return o.readyc
}

var (
	offlineX509Cert  *x509.Certificate
	offlineCerts     []webrtc.Certificate
	offlineCertsErr  error
	offlineCertsOnce sync.Once
)

func loadCertificate() ([]webrtc.Certificate, *x509.Certificate, error) {
	offlineCertsOnce.Do(func() {
		certPem, extra := pem.Decode(campfireCert)
		if len(extra) > 0 {
			offlineCertsErr = fmt.Errorf("extra data after certificate")
			return
		}
		if certPem == nil {
			offlineCertsErr = fmt.Errorf("failed to decode certificate")
			return
		}
		keyPem, extra := pem.Decode(campfireKey)
		if len(extra) > 0 {
			offlineCertsErr = fmt.Errorf("extra data after key")
			return
		}
		if keyPem == nil {
			offlineCertsErr = fmt.Errorf("failed to decode key")
			return
		}
		cert, err := x509.ParseCertificate(certPem.Bytes)
		if err != nil {
			offlineCertsErr = fmt.Errorf("parse certificate: %w", err)
			return
		}
		offlineX509Cert = cert
		key, err := x509.ParsePKCS8PrivateKey(keyPem.Bytes)
		if err != nil {
			offlineCertsErr = fmt.Errorf("parse key: %w", err)
			return
		}
		offlineCerts = []webrtc.Certificate{webrtc.CertificateFromX509(key, cert)}
	})
	return offlineCerts, offlineX509Cert, offlineCertsErr
}

var waiterRemoteTemplate = template.Must(template.New("srv-remote-desc").Parse(`v=0
o=- 6920920643910646739 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=msid-semantic: WMS
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=ice-ufrag:{{ .Username }}
a=ice-pwd:{{ .Secret }}
a=fingerprint:sha-256 invalidFingerprint
a=setup:actpass
a=mid:0
a=sctp-port:5000
`))
