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

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
)

// WebRTCSignalOptions are options for configuring the WebRTC transport.
type WebRTCClientSignalOptions struct {
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

// NewWebRTCClientSignalTransport returns a new WebRTC signaling transport.
func NewWebRTCClientSignalTransport(opts WebRTCClientSignalOptions) transport.WebRTCSignalTransport {
	return &webrtcClientSignalTransport{
		WebRTCClientSignalOptions: opts,
		descriptionc:              make(chan webrtc.SessionDescription, 1),
		candidatec:                make(chan webrtc.ICECandidateInit, 16),
		errc:                      make(chan error, 1),
		cancel:                    func() {},
	}
}

type webrtcClientSignalTransport struct {
	WebRTCClientSignalOptions

	stream       v1.WebRTC_StartDataChannelClient
	descriptionc chan webrtc.SessionDescription
	candidatec   chan webrtc.ICECandidateInit
	errc         chan error
	mu           sync.Mutex
	cancel       context.CancelFunc
}

// Start starts the transport.
func (rt *webrtcClientSignalTransport) Start(ctx context.Context) error {
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
func (rt *webrtcClientSignalTransport) SendDescription(ctx context.Context, desc webrtc.SessionDescription) error {
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
		return fmt.Errorf("send SDP description: %w", err)
	}
	return nil
}

// SendCandidate sends an ICE candidate to the remote peer.
func (rt *webrtcClientSignalTransport) SendCandidate(ctx context.Context, candidate webrtc.ICECandidateInit) error {
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
		return fmt.Errorf("send ICE candidate: %w", err)
	}
	return nil
}

// Candidates returns a channel of ICE candidates received from the remote peer.
func (rt *webrtcClientSignalTransport) Candidates() <-chan webrtc.ICECandidateInit {
	return rt.candidatec
}

// Descriptions returns a channel of SDP descriptions received from the remote peer.
func (rt *webrtcClientSignalTransport) Descriptions() <-chan webrtc.SessionDescription {
	return rt.descriptionc
}

// Error returns a channel that receives any error encountered during signaling.
func (rt *webrtcClientSignalTransport) Error() <-chan error {
	return rt.errc
}

// Close closes the transport.
func (rt *webrtcClientSignalTransport) Close() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	defer rt.cancel()
	return rt.stream.CloseSend()
}

func (rt *webrtcClientSignalTransport) handleNegotiateStream(ctx context.Context, conn *grpc.ClientConn, stream v1.WebRTC_StartDataChannelClient) {
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
