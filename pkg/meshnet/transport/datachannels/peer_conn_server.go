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
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/pion/webrtc/v3"
	v1 "github.com/webmeshproj/api/go/v1"

	"github.com/webmeshproj/webmesh/pkg/common"
	"github.com/webmeshproj/webmesh/pkg/context"
)

// PeerConnectionServer represents a connection to a peer where we
// forward traffic for the other end.
type PeerConnectionServer struct {
	// PeerConnection is the underlying WebRTC peer connection.
	*webrtc.PeerConnection
	// offer is the offer to be sent to the peer.
	offer webrtc.SessionDescription
	// offerJSON is the JSON-encoded offer to be sent to the peer.
	offerJSON []byte
	// proto is the protocol used for the connection.
	proto string
	// srcAddress is the source address of the client that initiated the
	// connection.
	srcAddress string
	// address is the destination address of the connection.
	dstAddress string
	// logger is the logger to use for the connection.
	logger *slog.Logger
	// candidatec is a channel that receives ICE candidates.
	candidatec chan string
	// closec is a channel that is closed when the connection is closed.
	closec chan struct{}
	// readyc is a channel that is closed when the connection is ready.
	readyc chan struct{}
	// dataChannel is the data channel used for the connection.
	channels *webrtc.DataChannel
}

// Offer represents an offer to be sent to a peer.
type OfferOptions struct {
	// Proto is the protocol used for the connection.
	// Defaults to "tcp".
	Proto string
	// SrcAddress is the source address and port of the client that
	// initiated the connection.
	SrcAddress string
	// DstAddress is the destination address and port of the connection.
	DstAddress string
	// STUNServers is a list of STUN servers to use for the connection.
	STUNServers []string
}

// NewPeerConnectionServer creates a new peer connection server with the given options.
func NewPeerConnectionServer(ctx context.Context, opts *OfferOptions) (*PeerConnectionServer, error) {
	if opts.Proto == "" {
		opts.Proto = "tcp"
	}
	s := webrtc.SettingEngine{}
	s.DetachDataChannels()
	s.SetIncludeLoopbackCandidate(true)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(s))
	conn, err := api.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs: opts.STUNServers,
				// TODO: Authentication
				Username:       "-",
				Credential:     "-",
				CredentialType: webrtc.ICECredentialTypePassword,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create peer connection: %w", err)
	}
	pc := &PeerConnectionServer{
		PeerConnection: conn,
		proto:          opts.Proto,
		srcAddress:     opts.SrcAddress,
		dstAddress:     opts.DstAddress,
		logger: context.LoggerFrom(ctx).With(
			slog.String("proto", opts.Proto),
			slog.String("src", opts.SrcAddress),
			slog.String("dst", opts.DstAddress),
		),
		candidatec: make(chan string, 16),
		readyc:     make(chan struct{}),
		closec:     make(chan struct{}),
	}
	var mu sync.Mutex
	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		mu.Lock()
		defer mu.Unlock()
		pc.logger.Debug("ICE connection state changed", slog.String("state", state.String()))
		if state == webrtc.ICEConnectionStateConnected {
			select {
			case <-pc.closec:
				return
			default:
				close(pc.readyc)
			}
		}
		if state == webrtc.ICEConnectionStateFailed || state == webrtc.ICEConnectionStateCompleted {
			select {
			case <-pc.closec:
				return
			default:
				close(pc.closec)
			}
			pc.logger.Info("ICE connection finished, closing peer connection")
			err := pc.Close()
			if err != nil {
				pc.logger.Error("Failed to close peer connection", slog.String("error", err.Error()))
			}
		}
	})
	pc.OnICECandidate(pc.onICECandidate)
	dc, err := pc.CreateDataChannel(
		v1.DataChannel_CHANNELS.String(), &webrtc.DataChannelInit{
			Protocol:   common.Pointer("tcp"),
			Ordered:    common.Pointer(true),
			Negotiated: common.Pointer(true),
			ID:         common.Pointer(uint16(0)),
		})
	if err != nil {
		return nil, err
	}
	pc.channels = dc
	pc.channels.OnClose(pc.onDataChannelClose)
	pc.channels.OnOpen(pc.onDataChannelOpen)
	offer, err := conn.CreateOffer(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create offer: %w", err)
	}
	err = conn.SetLocalDescription(offer)
	if err != nil {
		return nil, fmt.Errorf("failed to set local description: %w", err)
	}
	pc.offer = offer
	pc.offerJSON, err = json.Marshal(offer)
	return pc, err
}

// Offer returns the offer to be sent to the peer.
func (pc *PeerConnectionServer) Offer() string {
	return string(pc.offerJSON)
}

// AnswerOffer answers the given offer from the peer.
func (pc *PeerConnectionServer) AnswerOffer(answer string) error {
	var answerInit webrtc.SessionDescription
	err := json.Unmarshal([]byte(answer), &answerInit)
	if err != nil {
		return err
	}
	return pc.SetRemoteDescription(answerInit)
}

// Candidates returns a channel that will receive potential
// ICE candidates for the peer.
func (pc *PeerConnectionServer) Candidates() <-chan string {
	return pc.candidatec
}

// AddCandidate adds an ICE candidate to the peer connection.
func (pc *PeerConnectionServer) AddCandidate(cand string) error {
	var candidate webrtc.ICECandidateInit
	err := json.Unmarshal([]byte(cand), &candidate)
	if err != nil {
		return err
	}
	return pc.AddICECandidate(candidate)
}

// Closed returns a channel that will be closed when the peer connection
// is closed.
func (pc *PeerConnectionServer) Closed() <-chan struct{} {
	return pc.closec
}

// Ready returns a channel that will be closed when the peer connection
// is ready.
func (pc *PeerConnectionServer) Ready() <-chan struct{} {
	return pc.readyc
}

// IsClosed returns true if the peer connection is closed.
func (pc *PeerConnectionServer) IsClosed() bool {
	select {
	case <-pc.closec:
		return true
	default:
		return false
	}
}

func (pc *PeerConnectionServer) onICECandidate(c *webrtc.ICECandidate) {
	if c == nil {
		return
	}
	pc.logger.Debug("Received ICE candidate", slog.Any("candidate", c))
	pc.candidatec <- c.ToJSON().Candidate
}

func (pc *PeerConnectionServer) onDataChannelClose() {
	pc.logger.Debug("data channel has closed")
}

func (pc *PeerConnectionServer) onDataChannelOpen() {
	pc.logger.Info("data channel has opened")
	candidatePair, err := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
	if err != nil {
		pc.logger.Error("failed to get selected candidate pair", slog.String("error", err.Error()))
		return
	}
	pc.logger.Info("selected candidate pair", slog.Any("candidatePair", candidatePair))
	rw, err := pc.channels.Detach()
	if err != nil {
		pc.logger.Error("failed to detach data channel", slog.String("error", err.Error()))
		return
	}
	defer pc.Close()
	defer rw.Close()
	for {
		select {
		case <-pc.closec:
			return
		default:
		}
		// ChannelID comes as a uint32 over the wire
		var channelID uint32
		err := binary.Read(rw, binary.BigEndian, &channelID)
		if err != nil {
			pc.logger.Error("failed to read channel ID", slog.String("error", err.Error()))
			return
		}
		// Create a data channel for the incoming connection
		log := pc.logger.
			With(slog.Uint64("channelID", uint64(channelID))).
			With(slog.String("remote", pc.dstAddress)).
			With(slog.String("protocol", pc.proto))
		log.Info("received incoming connection, creating channel")
		d, err := pc.CreateDataChannel(
			v1.DataChannel_CONNECTIONS.String(), &webrtc.DataChannelInit{
				Protocol:   &pc.proto,
				Ordered:    common.Pointer(true),
				Negotiated: common.Pointer(true),
				ID:         common.Pointer(uint16(channelID)),
			})
		if err != nil {
			log.Error("failed to create data channel",
				slog.String("error", err.Error()))
			return
		}
		d.OnClose(func() {
			log.Debug("data channel has closed")
		})
		d.OnOpen(func() {
			log.Info("data channel has opened, dialing remote")
			defer d.Close()
			dconn, err := d.Detach()
			if err != nil {
				log.Error("failed to detach data channel",
					slog.String("error", err.Error()))
				return
			}
			conn, err := net.Dial(pc.proto, pc.dstAddress)
			if err != nil {
				log.Error("failed to dial remote", slog.String("error", err.Error()))
				return
			}
			defer conn.Close()
			log.Info("connected to remote")
			go func() {
				_, err := io.Copy(conn, dconn)
				if err != nil {
					log.Error("failed to copy from data channel to remote",
						slog.String("error", err.Error()))
				}
			}()
			_, err = io.Copy(dconn, conn)
			if err != nil {
				log.Error("failed to copy from remote to data channel",
					slog.String("error", err.Error()))
			}
		})
	}
}
