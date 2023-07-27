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
	"net"

	"github.com/pion/webrtc/v3"
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/util"
)

// ServerPeerConnection represents a connection to a peer where we
// forward traffic for the other end.
type ServerPeerConnection struct {
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

// NewServerPeerConnection creates a new peer connection with the given options.
func NewServerPeerConnection(opts *OfferOptions) (*ServerPeerConnection, error) {
	if opts.Proto == "" {
		opts.Proto = "tcp"
	}
	conn, err := WebRTC.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{URLs: opts.STUNServers},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create peer connection: %w", err)
	}
	pc := &ServerPeerConnection{
		PeerConnection: conn,
		proto:          opts.Proto,
		srcAddress:     opts.SrcAddress,
		dstAddress:     opts.DstAddress,
		logger: slog.Default().With(
			slog.String("proto", opts.Proto),
			slog.String("src", opts.SrcAddress),
			slog.String("dst", opts.DstAddress),
		),
		candidatec: make(chan string, 16),
		closec:     make(chan struct{}),
	}
	pc.OnICEConnectionStateChange(pc.onICEConnectionStateChange)
	pc.OnICECandidate(pc.onICECandidate)
	dc, err := pc.CreateDataChannel(
		v1.DataChannel_CHANNELS.String(), &webrtc.DataChannelInit{
			Protocol:   util.Pointer("tcp"),
			Ordered:    util.Pointer(true),
			Negotiated: util.Pointer(true),
			ID:         util.Pointer(uint16(0)),
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
func (pc *ServerPeerConnection) Offer() string {
	return string(pc.offerJSON)
}

// AnswerOffer answers the given offer from the peer.
func (pc *ServerPeerConnection) AnswerOffer(answer string) error {
	var answerInit webrtc.SessionDescription
	err := json.Unmarshal([]byte(answer), &answerInit)
	if err != nil {
		return err
	}
	return pc.SetRemoteDescription(answerInit)
}

// Candidates returns a channel that will receive potential
// ICE candidates for the peer.
func (pc *ServerPeerConnection) Candidates() <-chan string {
	return pc.candidatec
}

// AddCandidate adds an ICE candidate to the peer connection.
func (pc *ServerPeerConnection) AddCandidate(candidate string) error {
	return pc.AddICECandidate(webrtc.ICECandidateInit{
		Candidate: candidate,
	})
}

// Closed returns a channel that will be closed when the peer connection
// is closed.
func (pc *ServerPeerConnection) Closed() <-chan struct{} {
	return pc.closec
}

// IsClosed returns true if the peer connection is closed.
func (pc *ServerPeerConnection) IsClosed() bool {
	select {
	case <-pc.closec:
		return true
	default:
		return false
	}
}

func (pc *ServerPeerConnection) onICEConnectionStateChange(state webrtc.ICEConnectionState) {
	pc.logger.Debug("ICE connection state changed", slog.String("state", state.String()))
	closeAll := func() {
		select {
		case <-pc.candidatec:
		default:
			defer close(pc.candidatec)
		}
		select {
		case <-pc.closec:
		default:
			defer close(pc.closec)
		}
	}
	if state == webrtc.ICEConnectionStateConnected {
		defer close(pc.candidatec)
	}
	if state == webrtc.ICEConnectionStateFailed {
		defer closeAll()
		pc.logger.Info("ICE connection failed, closing peer connection")
		err := pc.Close()
		if err != nil {
			pc.logger.Error("Failed to close peer connection", slog.String("error", err.Error()))
		}
	}
	if state == webrtc.ICEConnectionStateCompleted {
		defer closeAll()
		pc.logger.Info("ICE connection completed, closing peer connection")
		err := pc.Close()
		if err != nil {
			pc.logger.Error("Failed to close peer connection", slog.String("error", err.Error()))
		}
	}
}

func (pc *ServerPeerConnection) onICECandidate(c *webrtc.ICECandidate) {
	if c == nil {
		return
	}
	select {
	case <-pc.closec:
		return
	case <-pc.candidatec:
		return
	default:
	}
	pc.logger.Debug("Received ICE candidate", slog.Any("candidate", c))
	pc.candidatec <- c.ToJSON().Candidate
}

func (pc *ServerPeerConnection) onDataChannelClose() {
	pc.logger.Debug("data channel has closed")
}

func (pc *ServerPeerConnection) onDataChannelOpen() {
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
				Ordered:    util.Pointer(true),
				Negotiated: util.Pointer(true),
				ID:         util.Pointer(uint16(channelID)),
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
