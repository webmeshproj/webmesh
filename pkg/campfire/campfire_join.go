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
	"bufio"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/pion/datachannel"
	"github.com/pion/webrtc/v3"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/util"
)

// CampFire is a connection to one or more peers sharing the same pre-shared
// key.
type CampFire struct {
	loc  *Location
	host host.Host
	dht  *dht.IpfsDHT
	// pc     *webrtc.PeerConnection
	// dc     datachannel.ReadWriteCloser
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
func Join(ctx context.Context, opts Options) (*CampFire, error) {
	var err error
	cf := CampFire{
		errc:    make(chan error, 3),
		readyc:  make(chan struct{}),
		acceptc: make(chan datachannel.ReadWriteCloser),
		closec:  make(chan struct{}),
	}
	cf.log = context.LoggerFrom(ctx).With("protocol", "campfire")
	cf.loc, err = Find(opts.PSK, opts.TURNServers)
	if err != nil {
		return nil, fmt.Errorf("find current camp fire: %w", err)
	}
	cf.log.Debug("found camp fire", "secret", cf.loc.Secret, "turn", cf.loc.TURNServer)
	cf.host, err = libp2p.New(libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"))
	if err != nil {
		return nil, fmt.Errorf("new libp2p host: %w", err)
	}
	cf.host.SetStreamHandler(Protocol, cf.onNewStream)
	cf.log.Debug("libp2p host created", "id", cf.host.ID(), "addrs", cf.host.Addrs())
	cf.dht, err = dht.New(ctx, cf.host)
	if err != nil {
		return nil, fmt.Errorf("new DHT: %w", err)
	}
	cf.log.Debug("bootstrapping the DHT")
	if err := cf.dht.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrap DHT: %w", err)
	}
	var wg sync.WaitGroup
	for _, peerAddr := range dht.DefaultBootstrapPeers {
		peerinfo, _ := peer.AddrInfoFromP2pAddr(peerAddr)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cf.host.Connect(ctx, *peerinfo); err != nil {
				cf.log.Warn("Error connectiong to host", "error", err.Error())
			} else {
				cf.log.Debug("Connection established with bootstrap node", "peer", *peerinfo)
			}
		}()
	}
	wg.Wait()
	routingDiscovery := routing.NewRoutingDiscovery(cf.dht)
	dutil.Advertise(ctx, routingDiscovery, cf.loc.Secret)
	cf.log.Debug("DHT bootstrapped, waiting by the camp fire...")
	go func() {
		// Wait for a peer to announce the camp fire
		peerChan, err := routingDiscovery.FindPeers(ctx, cf.loc.Secret)
		if err != nil {
			cf.errc <- fmt.Errorf("find peers: %w", err)
			return
		}
		for pi := range peerChan {
			go cf.onFoundPeer(ctx, pi)
		}
	}()
	return &cf, nil
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
	return nil
}

func (cf *CampFire) Errors() <-chan error {
	return cf.errc
}

func (cf *CampFire) Ready() <-chan struct{} {
	return cf.readyc
}

func (cf *CampFire) onFoundPeer(ctx context.Context, peer peer.AddrInfo) {
	if peer.ID == cf.host.ID() {
		return
	}
	cf.log.Debug("starting negotiation stream with peer", "peer", peer.ID)
	stream, err := cf.host.NewStream(ctx, peer.ID, Protocol)
	if err != nil {
		cf.errc <- fmt.Errorf("new stream: %w", err)
		return
	}
	rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))
	s := webrtc.SettingEngine{}
	s.DetachDataChannels()
	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))
	conn, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs:           []string{cf.loc.TURNServer},
				Username:       "-",
				Credential:     cf.loc.Secret,
				CredentialType: webrtc.ICECredentialTypePassword,
			},
		},
		PeerIdentity: cf.loc.Secret,
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
		candidate := c.ToJSON().Candidate
		msg := message{
			Candidate: candidate,
		}
		out, err := json.Marshal(msg)
		if err != nil {
			cf.errc <- fmt.Errorf("marshal candidate: %w", err)
			return
		}
		_, err = rw.Write(append(out, []byte("\n")...))
		if err != nil {
			cf.errc <- fmt.Errorf("write candidate: %w", err)
			return
		}
		err = rw.Flush()
		if err != nil {
			cf.errc <- fmt.Errorf("flush candidate: %w", err)
			return
		}
	})
	dc, err := conn.CreateDataChannel(cf.loc.Secret, &webrtc.DataChannelInit{
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
	// Send the offer
	var msg message
	out, err := json.Marshal(offer)
	if err != nil {
		cf.errc <- fmt.Errorf("marshal offer: %w", err)
		return
	}
	msg.SDP = string(out)
	out, err = json.Marshal(msg)
	if err != nil {
		cf.errc <- fmt.Errorf("marshal message: %w", err)
		return
	}
	_, err = rw.Write(append(out, []byte("\n")...))
	if err != nil {
		cf.errc <- fmt.Errorf("write offer: %w", err)
		return
	}
	err = rw.Flush()
	if err != nil {
		cf.errc <- fmt.Errorf("flush offer: %w", err)
		return
	}
	cf.log.Debug("wrote offer to peer", "peer", peer.ID)
	// Handle negotiation
	go func() {
		var answerDone bool
		for {
			data, err := rw.ReadString('\n')
			if err != nil {
				cf.errc <- fmt.Errorf("read string: %w", err)
				return
			}
			if data == "" {
				return
			}
			var msg message
			err = json.Unmarshal([]byte(data), &msg)
			if err != nil {
				cf.errc <- fmt.Errorf("unmarshal message: %w", err)
				return
			}
			if msg.SDP != "" && !answerDone {
				cf.log.Debug("got remote description", "sdp", msg.SDP)
				// Set our remote description
				var answer webrtc.SessionDescription
				err := json.Unmarshal([]byte(msg.SDP), &answer)
				if err != nil {
					cf.errc <- fmt.Errorf("unmarshal offer: %w", err)
					return
				}
				err = conn.SetRemoteDescription(answer)
				if err != nil {
					cf.errc <- fmt.Errorf("set remote description: %w", err)
					return
				}
				answerDone = true
			}
			if msg.Candidate != "" {
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

func (cf *CampFire) onNewStream(stream network.Stream) {
	cf.log.Info("new stream", "peer", stream.Conn().RemotePeer())
	rw := bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream))
	s := webrtc.SettingEngine{}
	s.DetachDataChannels()
	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))
	conn, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs:           []string{cf.loc.TURNServer},
				Username:       "-",
				Credential:     cf.loc.Secret,
				CredentialType: webrtc.ICECredentialTypePassword,
			},
		},
		PeerIdentity: cf.loc.Secret,
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
		candidate := c.ToJSON().Candidate
		msg := message{
			Candidate: candidate,
		}
		out, err := json.Marshal(msg)
		if err != nil {
			cf.errc <- fmt.Errorf("marshal candidate: %w", err)
			return
		}
		_, err = rw.Write(append(out, []byte("\n")...))
		if err != nil {
			cf.errc <- fmt.Errorf("write candidate: %w", err)
			return
		}
		err = rw.Flush()
		if err != nil {
			cf.errc <- fmt.Errorf("flush candidate: %w", err)
			return
		}
	})
	dc, err := conn.CreateDataChannel(cf.loc.Secret, &webrtc.DataChannelInit{
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
		var answerDone bool
		for {
			data, err := rw.ReadString('\n')
			if err != nil {
				cf.errc <- fmt.Errorf("read string: %w", err)
				return
			}
			if data == "" {
				return
			}
			cf.log.Debug("got message", "message", data)
			var msg message
			err = json.Unmarshal([]byte(data), &msg)
			if err != nil {
				cf.errc <- fmt.Errorf("unmarshal message: %w", err)
				return
			}
			if msg.SDP != "" && !answerDone {
				// Set our remote description
				cf.log.Debug("got remote description", "sdp", msg.SDP)
				var offer webrtc.SessionDescription
				err = json.Unmarshal([]byte(msg.SDP), &offer)
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
				var msg message
				out, err := json.Marshal(answer)
				if err != nil {
					cf.errc <- fmt.Errorf("marshal answer: %w", err)
					return
				}
				msg.SDP = string(out)
				out, err = json.Marshal(msg)
				if err != nil {
					cf.errc <- fmt.Errorf("marshal message: %w", err)
					return
				}
				_, err = rw.Write(append(out, []byte("\n")...))
				if err != nil {
					cf.errc <- fmt.Errorf("write answer: %w", err)
					return
				}
				err = rw.Flush()
				if err != nil {
					cf.errc <- fmt.Errorf("flush answer: %w", err)
					return
				}
				answerDone = true
			}
			if msg.Candidate != "" {
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

type message struct {
	Candidate string
	SDP       string
}
