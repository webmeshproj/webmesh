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
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/pion/webrtc/v3"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/util"
)

const wgBufferSize = 1500

type WireGuardProxyServer struct {
	*webrtc.PeerConnection
	candidatec chan string
	messages   chan []byte
	closec     chan struct{}
	offer      []byte
}

func NewWireGuardProxyServer(ctx context.Context, stunServers []string, targetPort uint16) (*WireGuardProxyServer, error) {
	conn, err := WebRTC.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{URLs: stunServers},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("new peer connection: %w", err)
	}
	pc := &WireGuardProxyServer{
		PeerConnection: conn,
		candidatec:     make(chan string, 1),
		messages:       make(chan []byte, 1),
		closec:         make(chan struct{}),
	}
	log := context.LoggerFrom(ctx)
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
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
		log.Debug("Received ICE candidate", slog.Any("candidate", c))
		pc.candidatec <- c.ToJSON().Candidate
	})
	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
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
			candidatePair, err := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
			if err != nil {
				log.Error("Failed to get selected candidate pair", slog.String("error", err.Error()))
				return
			}
			log.Debug("ICE connection established", slog.Any("local", candidatePair.Local), slog.Any("remote", candidatePair.Remote))
		}
		if state == webrtc.ICEConnectionStateCompleted || state == webrtc.ICEConnectionStateFailed {
			defer closeAll()
			log.Info("ICE connection has closed", "reason", state.String())
		}
	})
	dc, err := pc.CreateDataChannel("wireguard-proxy", &webrtc.DataChannelInit{
		Ordered:    util.Pointer(true),
		Protocol:   util.Pointer("udp"),
		Negotiated: util.Pointer(true),
		ID:         util.Pointer(uint16(0)),
	})
	if err != nil {
		return nil, fmt.Errorf("create data channel: %w", err)
	}
	dc.OnOpen(func() {
		log.Info("Server side datachannel opened")
		rw, err := dc.Detach()
		if err != nil {
			log.Error("Failed to detach data channel", slog.String("error", err.Error()))
			return
		}
		wgiface, err := net.DialUDP("udp4", nil, &net.UDPAddr{
			IP:   net.IPv4zero,
			Port: int(targetPort),
		})
		if err != nil {
			defer rw.Close()
			log.Error("Failed to dial UDP", slog.String("error", err.Error()))
			return
		}
		log.Info("Starting WireGuard proxy")
		go func() {
			defer log.Info("WireGuard proxy from local to datachannel stopped")
			defer wgiface.Close()
			buf := make([]byte, wgBufferSize)
			for {
				select {
				case <-pc.closec:
					return
				default:
				}
				err := wgiface.SetReadDeadline(time.Now().Add(time.Second))
				if err != nil {
					log.Error("Failed to set read deadline", slog.String("error", err.Error()))
					return
				}
				n, err := wgiface.Read(buf[0:])
				if err != nil {
					if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
						continue
					}
					log.Error("Failed to read from interface", slog.String("error", err.Error()))
					return
				}
				_, err = rw.Write(buf[:n])
				if err != nil {
					log.Error("Failed to write message", slog.String("error", err.Error()))
					return
				}
			}
		}()
		defer log.Info("WireGuard proxy from datachannel to local stopped")
		defer pc.Close()
		buf := make([]byte, wgBufferSize)
		for {
			select {
			case <-pc.closec:
				return
			default:
			}
			n, err := rw.Read(buf[0:])
			if err != nil {
				if err == io.EOF {
					return
				}
				log.Error("Failed to read from data channel", slog.String("error", err.Error()))
				return
			}
			_, err = wgiface.Write(buf[:n])
			if err != nil {
				log.Error("Failed to write to interface", slog.String("error", err.Error()))
				return
			}
		}
	})
	dc.OnClose(func() {
		log.Info("Data channel closed")
	})
	offer, err := conn.CreateOffer(nil)
	if err != nil {
		return nil, fmt.Errorf("create offer: %w", err)
	}
	err = conn.SetLocalDescription(offer)
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

// AnswerOffer answers the given offer from the peer.
func (w *WireGuardProxyServer) AnswerOffer(answer string) error {
	var answerInit webrtc.SessionDescription
	err := json.Unmarshal([]byte(answer), &answerInit)
	if err != nil {
		return err
	}
	return w.SetRemoteDescription(answerInit)
}

// Candidates returns a channel that will receive potential
// ICE candidates for the peer.
func (w *WireGuardProxyServer) Candidates() <-chan string {
	return w.candidatec
}

// AddCandidate adds an ICE candidate to the peer connection.
func (w *WireGuardProxyServer) AddCandidate(candidate string) error {
	return w.AddICECandidate(webrtc.ICECandidateInit{
		Candidate: candidate,
	})
}

// Closed returns a channel that will be closed when the peer
// connection is closed.
func (w *WireGuardProxyServer) Closed() <-chan struct{} {
	return w.closec
}

type WireGuardProxyClient struct {
	*webrtc.PeerConnection
	localAddr *net.UDPAddr
	readyc    chan struct{}
	closec    chan struct{}
}

// NewWireGuardProxyClient creates a new WireGuard proxy client.
func NewWireGuardProxyClient(ctx context.Context, cli v1.WebRTCClient, targetNode string, targetPort int) (*WireGuardProxyClient, error) {
	log := context.LoggerFrom(ctx)
	neg, err := cli.StartDataChannel(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start data channel negotiation: %w", err)
	}
	closeNeg := func() {
		if err := neg.CloseSend(); err != nil {
			log.Error("failed to close negotiation stream", "error", err.Error())
		}
	}
	err = neg.Send(&v1.StartDataChannelRequest{
		NodeId: targetNode,
		Proto:  "udp",
		Dst:    "",
		Port:   0,
	})
	if err != nil {
		defer closeNeg()
		return nil, fmt.Errorf("failed to send data channel negotiation request: %w", err)
	}
	// Wait for an offer from the controller
	resp, err := neg.Recv()
	if err != nil {
		defer closeNeg()
		return nil, fmt.Errorf("failed to receive offer: %w", err)
	}
	var offer webrtc.SessionDescription
	if err := json.Unmarshal([]byte(resp.GetOffer()), &offer); err != nil {
		defer closeNeg()
		return nil, fmt.Errorf("failed to unmarshal SDP: %w", err)
	}
	c, err := WebRTC.NewPeerConnection(webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{{URLs: resp.StunServers}},
	})
	if err != nil {
		defer closeNeg()
		return nil, fmt.Errorf("failed to create peer connection: %w", err)
	}
	pc := &WireGuardProxyClient{
		PeerConnection: c,
		readyc:         make(chan struct{}),
		closec:         make(chan struct{}),
	}
	errs := make(chan error, 10)
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		err := neg.Send(&v1.StartDataChannelRequest{
			Candidate: c.ToJSON().Candidate,
		})
		if err != nil {
			defer closeNeg()
			errs <- fmt.Errorf("failed to send ICE candidate: %w", err)
		}
	})
	pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) {
		if s == webrtc.ICEConnectionStateConnected {
			closeNeg()
			close(pc.readyc)
			candidatePair, err := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
			if err != nil {
				log.Error("Failed to get selected candidate pair", slog.String("error", err.Error()))
				return
			}
			log.Debug("ICE connection established", slog.Any("local", candidatePair.Local), slog.Any("remote", candidatePair.Remote))
			return
		}
		if s == webrtc.ICEConnectionStateFailed || s == webrtc.ICEConnectionStateClosed || s == webrtc.ICEConnectionStateCompleted {
			select {
			case <-pc.closec:
				return
			default:
			}
			close(pc.closec)
			log.Info("ICE connection has closed", "reason", s.String())
		}
	})
	dc, err := pc.CreateDataChannel("wireguard-proxy", &webrtc.DataChannelInit{
		Ordered:    util.Pointer(true),
		Protocol:   util.Pointer("udp"),
		Negotiated: util.Pointer(true),
		ID:         util.Pointer(uint16(0)),
	})
	if err != nil {
		return nil, fmt.Errorf("create data channel: %w", err)
	}
	l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	pc.localAddr = l.LocalAddr().(*net.UDPAddr)
	dc.OnOpen(func() {
		log.Debug("Client side datachannel opened")
		var err error
		rw, err := dc.Detach()
		if err != nil {
			log.Error("Failed to detach data channel", slog.String("error", err.Error()))
			return
		}
		go func() {
			defer l.Close()
			buf := make([]byte, wgBufferSize)
			for {
				select {
				case <-pc.closec:
					return
				default:
				}
				err := l.SetReadDeadline(time.Now().Add(time.Second))
				if err != nil {
					log.Error("Failed to set read deadline", slog.String("error", err.Error()))
					return
				}
				n, err := l.Read(buf[0:])
				if err != nil {
					if e, ok := err.(net.Error); ok && e.Timeout() {
						continue
					}
					log.Error("Failed to read from proxy listener", slog.String("error", err.Error()))
					return
				}
				_, err = rw.Write(buf[:n])
				if err != nil {
					log.Error("Failed to send to data channel", slog.String("error", err.Error()))
					return
				}
			}
		}()
		defer pc.Close()
		buf := make([]byte, wgBufferSize)
		for {
			select {
			case <-pc.closec:
				return
			default:
			}
			n, err := rw.Read(buf[0:])
			if err != nil {
				if err == io.EOF {
					return
				}
				log.Error("Failed to read from data channel", slog.String("error", err.Error()))
				return
			}
			_, err = l.WriteTo(buf[:n], &net.UDPAddr{
				IP:   net.IPv4zero,
				Port: targetPort,
			})
			if err != nil {
				log.Error("Failed to write to interface", slog.String("error", err.Error()))
				return
			}
		}
	})
	err = pc.SetRemoteDescription(offer)
	if err != nil {
		defer closeNeg()
		return nil, fmt.Errorf("failed to set remote description: %w", err)
	}
	// Create and send an answer
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		defer closeNeg()
		return nil, fmt.Errorf("failed to create answer: %w", err)
	}
	marshaled, err := json.Marshal(answer)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal answer: %w", err)
	}
	err = pc.SetLocalDescription(answer)
	if err != nil {
		defer closeNeg()
		return nil, fmt.Errorf("failed to set local description: %w", err)
	}
	err = neg.Send(&v1.StartDataChannelRequest{
		Answer: string(marshaled),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to send answer: %w", err)
	}
	// Receive ICE candidates
	go func() {
		for {
			msg, err := neg.Recv()
			if err != nil {
				if err == io.EOF {
					break
				}
				errs <- fmt.Errorf("failed to receive ICE candidate: %w", err)
			}
			candidate := webrtc.ICECandidateInit{
				Candidate: msg.GetCandidate(),
			}
			if err := pc.AddICECandidate(candidate); err != nil {
				errs <- fmt.Errorf("failed to add ICE candidate: %w", err)
			}
		}
	}()
	select {
	case err := <-errs:
		return nil, err
	case <-time.After(10 * time.Second):
		return nil, fmt.Errorf("timed out waiting for data channel to open")
	case <-pc.readyc:
	}
	return pc, nil
}

func (w *WireGuardProxyClient) LocalAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: w.localAddr.Port,
	}
}

func (w *WireGuardProxyClient) Closed() <-chan struct{} {
	return w.closec
}
