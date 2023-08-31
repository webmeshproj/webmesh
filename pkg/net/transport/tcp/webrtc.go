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

package tcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sync"

	"github.com/pion/webrtc/v3"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
)

// ErrSignalTransportClosed is returned when a signal transport is closed
// by either side of the connection.
var ErrSignalTransportClosed = fmt.Errorf("signal transport closed")

// WebRTCExternalSignalOptions are options for configuring the WebRTC transport.
type WebRTCExternalSignalOptions struct {
	// Resolver is a resolver for looking up nodes with the ICE negotiation feature
	Resolver transport.FeatureResolver
	// Credentials are credentials to use for the gRPC connection.
	Credentials []grpc.DialOption
	// NodeID is the id of the remote node to signal to.
	NodeID string
	// TargetProto is the target protocol to request from the remote node.
	TargetProto string
	// TargetAddr is the target address to request from the remote node.
	TargetAddr netip.AddrPort
}

// NewExternalSignalTransport returns a new WebRTC signaling transport that attempts
// to negotiate a WebRTC connection from outside the mesh.
func NewExternalSignalTransport(opts WebRTCExternalSignalOptions) transport.WebRTCSignalTransport {
	return &webrtcExternalSignalTransport{
		WebRTCExternalSignalOptions: opts,
		descriptionc:                make(chan webrtc.SessionDescription, 1),
		candidatec:                  make(chan webrtc.ICECandidateInit, 16),
		errc:                        make(chan error, 1),
		cancel:                      func() {},
	}
}

// WebRTCInternalSignalOptions are options for configuring the WebRTC transport.
type WebRTCInternalSignalOptions struct {
	// Dialer is the dialer for calling the RPC server on the remote node.
	Dialer transport.NodeDialer
	// NodeID is the id of the remote node to signal to.
	NodeID string
	// TargetProto is the target protocol to request from the remote node.
	TargetProto string
	// TargetAddr is the target address to request from the remote node.
	TargetAddr netip.AddrPort
	// SourceAddr is optional and may be populated with the address
	// where the request originated.
	SourceAddr netip.Addr
	// STUNServers are the STUN servers to use for ICE negotiation.
	STUNServers []string
}

// NewWebRTCInternalSignalTransport returns a new WebRTC signaling transport that attempts
// to negotiate a WebRTC connection from within the mesh. This is typically used by servers
// receiving a request from a client.
func NewWebRTCInternalSignalTransport(opts WebRTCInternalSignalOptions) transport.WebRTCSignalTransport {
	return &webrtcInternalSignalTransport{
		WebRTCInternalSignalOptions: opts,
		descriptionc:                make(chan webrtc.SessionDescription, 1),
		candidatec:                  make(chan webrtc.ICECandidateInit, 16),
		errc:                        make(chan error, 1),
		cancel:                      func() {},
	}
}

type webrtcExternalSignalTransport struct {
	WebRTCExternalSignalOptions

	stream       v1.WebRTC_StartDataChannelClient
	descriptionc chan webrtc.SessionDescription
	candidatec   chan webrtc.ICECandidateInit
	errc         chan error
	mu           sync.Mutex
	cancel       context.CancelFunc
}

// Start starts the transport.
func (rt *webrtcExternalSignalTransport) Start(ctx context.Context) error {
	// Start the negotiation stream.
	rt.mu.Lock()
	defer rt.mu.Unlock()
	ctx, rt.cancel = context.WithCancel(ctx)
	addrs, err := rt.Resolver.Resolve(ctx, v1.Feature_ICE_NEGOTIATION)
	if err != nil {
		return fmt.Errorf("resolve signaling server: %w", err)
	}
	var conn *grpc.ClientConn
	for _, addr := range addrs {
		conn, err = grpc.Dial(addr.String(), rt.Credentials...)
		if err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("dial signaling server: %w", err)
	}
	cli := v1.NewWebRTCClient(conn)
	neg, err := cli.StartDataChannel(ctx)
	if err != nil {
		defer conn.Close()
		return fmt.Errorf("start negotiation stream: %w", err)
	}
	// Send the initial request over the wire
	err = neg.Send(&v1.StartDataChannelRequest{
		NodeId: rt.NodeID,
		Proto:  rt.TargetProto,
		Dst:    rt.TargetAddr.Addr().String(),
		Port:   uint32(rt.TargetAddr.Port()),
	})
	if err != nil {
		return fmt.Errorf("send negotiation request: %w", err)
	}
	rt.stream = neg
	go rt.handleNegotiateStream(ctx, conn, neg)
	return nil
}

// SendDescription sends an SDP offer or answer to the remote peer.
func (rt *webrtcExternalSignalTransport) SendDescription(ctx context.Context, desc webrtc.SessionDescription) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	b, err := json.Marshal(desc)
	if err != nil {
		return err
	}
	err = rt.stream.Send(&v1.StartDataChannelRequest{
		Answer: string(b),
	})
	if err != nil {
		if status.Code(err) == codes.Canceled {
			return ErrSignalTransportClosed
		}
		return fmt.Errorf("send SDP description: %w", err)
	}
	return nil
}

// SendCandidate sends an ICE candidate to the remote peer. If the peer has
// disconnected or the transport has been closed, this method returns an error.
func (rt *webrtcExternalSignalTransport) SendCandidate(ctx context.Context, candidate webrtc.ICECandidateInit) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	b, err := json.Marshal(candidate)
	if err != nil {
		return err
	}
	err = rt.stream.Send(&v1.StartDataChannelRequest{
		Candidate: string(b),
	})
	if err != nil {
		if status.Code(err) == codes.Canceled {
			return ErrSignalTransportClosed
		}
		return fmt.Errorf("send ICE candidate: %w", err)
	}
	return nil
}

// Candidates returns a channel of ICE candidates received from the remote peer.
func (rt *webrtcExternalSignalTransport) Candidates() <-chan webrtc.ICECandidateInit {
	return rt.candidatec
}

// Descriptions returns a channel of SDP descriptions received from the remote peer.
func (rt *webrtcExternalSignalTransport) Descriptions() <-chan webrtc.SessionDescription {
	return rt.descriptionc
}

// Error returns a channel that receives any error encountered during signaling.
func (rt *webrtcExternalSignalTransport) Error() <-chan error {
	return rt.errc
}

// Close closes the transport.
func (rt *webrtcExternalSignalTransport) Close() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	defer rt.cancel()
	return rt.stream.CloseSend()
}

func (rt *webrtcExternalSignalTransport) handleNegotiateStream(ctx context.Context, conn *grpc.ClientConn, stream v1.WebRTC_StartDataChannelClient) {
	log := context.LoggerFrom(ctx)
	defer close(rt.errc)
	defer conn.Close()
	for {
		msg, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return
			}
			log.Error("Failed to receive negotiation message", "error", err.Error())
			rt.errc <- err
			return
		}
		if msg.GetOffer() != "" {
			// Unmarshal and pass the offer to the caller.
			log.Debug("Received SDP offer from peer", "offer", msg.GetOffer())
			var desc webrtc.SessionDescription
			err := json.Unmarshal([]byte(msg.GetOffer()), &desc)
			if err != nil {
				log.Error("Failed to unmarshal SDP offer", "error", err.Error())
				rt.errc <- err
				return
			}
			rt.descriptionc <- desc
		}
		if msg.GetCandidate() != "" {
			// Unmarshal and pass the ICE candidate to the caller.
			log.Debug("Received ICE candidate from peer", "candidate", msg.GetCandidate())
			var candidate webrtc.ICECandidateInit
			err := json.Unmarshal([]byte(msg.GetCandidate()), &candidate)
			if err != nil {
				log.Error("Failed to unmarshal ICE candidate", "error", err.Error())
				rt.errc <- err
				return
			}
			rt.candidatec <- candidate
		}
	}
}

type webrtcInternalSignalTransport struct {
	WebRTCInternalSignalOptions

	stream       v1.Node_NegotiateDataChannelClient
	descriptionc chan webrtc.SessionDescription
	candidatec   chan webrtc.ICECandidateInit
	errc         chan error
	mu           sync.Mutex
	cancel       context.CancelFunc
}

// Start starts the transport.
func (rt *webrtcInternalSignalTransport) Start(ctx context.Context) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	ctx, rt.cancel = context.WithCancel(ctx)
	conn, err := rt.Dialer.Dial(ctx, rt.NodeID)
	if err != nil {
		return fmt.Errorf("dial node: %w", err)
	}
	stream, err := v1.NewNodeClient(conn).NegotiateDataChannel(ctx)
	if err != nil {
		defer conn.Close()
		return fmt.Errorf("negotiate data channel: %w", err)
	}
	// Send the initial request over the wire
	err = stream.Send(&v1.DataChannelNegotiation{
		Proto:       rt.TargetProto,
		Src:         rt.SourceAddr.String(),
		Dst:         rt.TargetAddr.Addr().String(),
		Port:        uint32(rt.TargetAddr.Port()),
		StunServers: rt.STUNServers,
	})
	if err != nil {
		return fmt.Errorf("send negotiation request: %w", err)
	}
	rt.stream = stream
	go rt.handleNegotiateStream(ctx, conn, stream)
	return nil
}

// SendDescription sends an SDP description to the remote peer.
func (rt *webrtcInternalSignalTransport) SendDescription(ctx context.Context, desc webrtc.SessionDescription) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	b, err := json.Marshal(desc)
	if err != nil {
		return err
	}
	err = rt.stream.Send(&v1.DataChannelNegotiation{
		Answer: string(b),
	})
	if err != nil {
		if status.Code(err) == codes.Canceled {
			return ErrSignalTransportClosed
		}
		return fmt.Errorf("send SDP description: %w", err)
	}
	return nil
}

// SendCandidate sends an ICE candidate to the remote peer.
func (rt *webrtcInternalSignalTransport) SendCandidate(ctx context.Context, candidate webrtc.ICECandidateInit) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	b, err := json.Marshal(candidate)
	if err != nil {
		return err
	}
	err = rt.stream.Send(&v1.DataChannelNegotiation{
		Candidate: string(b),
	})
	if err != nil {
		if status.Code(err) == codes.Canceled {
			return ErrSignalTransportClosed
		}
		return fmt.Errorf("send ICE candidate: %w", err)
	}
	return nil
}

// Candidates returns a channel of ICE candidates received from the remote peer.
func (rt *webrtcInternalSignalTransport) Candidates() <-chan webrtc.ICECandidateInit {
	return rt.candidatec
}

// Descriptions returns a channel of SDP descriptions received from the remote peer.
func (rt *webrtcInternalSignalTransport) Descriptions() <-chan webrtc.SessionDescription {
	return rt.descriptionc
}

// Error returns a channel that receives any error encountered during signaling.
// This channel will be closed when the transport is closed.
func (rt *webrtcInternalSignalTransport) Error() <-chan error {
	return rt.errc
}

// Close closes the transport.
func (rt *webrtcInternalSignalTransport) Close() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	defer rt.cancel()
	return rt.stream.CloseSend()
}

func (rt *webrtcInternalSignalTransport) handleNegotiateStream(ctx context.Context, conn *grpc.ClientConn, stream v1.Node_NegotiateDataChannelClient) {
	log := context.LoggerFrom(ctx)
	defer close(rt.errc)
	defer conn.Close()
	for {
		msg, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return
			}
			log.Error("Failed to receive negotiation message", "error", err.Error())
			rt.errc <- err
			return
		}
		if msg.GetOffer() != "" {
			// Unmarshal and pass the offer to the caller.
			log.Debug("Received SDP offer from peer", "offer", msg.GetOffer())
			var desc webrtc.SessionDescription
			err := json.Unmarshal([]byte(msg.GetOffer()), &desc)
			if err != nil {
				log.Error("Failed to unmarshal SDP offer", "error", err.Error())
				rt.errc <- err
				return
			}
			rt.descriptionc <- desc
		}
		if msg.GetCandidate() != "" {
			// Unmarshal and pass the ICE candidate to the caller.
			log.Debug("Received ICE candidate from peer", "candidate", msg.GetCandidate())
			var candidate webrtc.ICECandidateInit
			err := json.Unmarshal([]byte(msg.GetCandidate()), &candidate)
			if err != nil {
				log.Error("Failed to unmarshal ICE candidate", "error", err.Error())
				rt.errc <- err
				return
			}
			rt.candidatec <- candidate
		}
	}
}
