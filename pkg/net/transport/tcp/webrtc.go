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
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/pion/webrtc/v3"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
)

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
// to negotiate a WebRTC connection using the Webmesh WebRTC signaling server. This is
// typically used by clients trying to create a proxy connection to a server.
func NewExternalSignalTransport(opts WebRTCExternalSignalOptions) transport.WebRTCSignalTransport {
	return &webrtcExternalSignalTransport{
		WebRTCExternalSignalOptions: opts,
		candidatec:                  make(chan webrtc.ICECandidateInit, 16),
		errc:                        make(chan error, 1),
		cancel:                      func() {},
		closec:                      make(chan struct{}),
	}
}

type webrtcExternalSignalTransport struct {
	WebRTCExternalSignalOptions

	stream            v1.WebRTC_StartDataChannelClient
	turnServers       []webrtc.ICEServer
	remoteDescription webrtc.SessionDescription
	candidatec        chan webrtc.ICECandidateInit
	errc              chan error
	cancel            context.CancelFunc
	closec            chan struct{}
	mu                sync.Mutex
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
	if len(addrs) == 0 {
		return errors.New("no signaling servers found")
	}
	var conn *grpc.ClientConn
Connect:
	for _, addr := range addrs {
		var tries int
		maxRetries := 5
		for tries < maxRetries {
			conn, err = grpc.Dial(addr.String(), rt.Credentials...)
			if err == nil {
				break Connect
			}
			tries++
			if tries < maxRetries {
				time.Sleep(time.Second)
			}
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
	// Wait for the response
	resp, err := neg.Recv()
	if err != nil {
		return fmt.Errorf("receive negotiation response: %w", err)
	}
	var offer webrtc.SessionDescription
	err = json.Unmarshal([]byte(resp.GetOffer()), &offer)
	if err != nil {
		return fmt.Errorf("unmarshal SDP offer: %w", err)
	}
	rt.remoteDescription = offer
	rt.turnServers = make([]webrtc.ICEServer, len(resp.GetStunServers()))
	for i, server := range resp.GetStunServers() {
		rt.turnServers[i] = webrtc.ICEServer{
			URLs: []string{server},
			// TODO: Authentication
			Username:       rt.NodeID,
			Credential:     rt.NodeID,
			CredentialType: webrtc.ICECredentialTypePassword,
		}
	}
	rt.stream = neg
	go rt.handleNegotiateStream(ctx, conn, neg)
	return nil
}

// TURNServers returns a list of TURN servers configured for the transport.
func (rt *webrtcExternalSignalTransport) TURNServers() []webrtc.ICEServer {
	return rt.turnServers
}

// Candidates returns a channel of ICE candidates received from the remote peer.
func (rt *webrtcExternalSignalTransport) Candidates() <-chan webrtc.ICECandidateInit {
	return rt.candidatec
}

// RemoteDescription returns the SDP description received from the remote peer.
func (rt *webrtcExternalSignalTransport) RemoteDescription() webrtc.SessionDescription {
	return rt.remoteDescription
}

// Error returns a channel that receives any error encountered during signaling.
func (rt *webrtcExternalSignalTransport) Error() <-chan error {
	return rt.errc
}

// SendDescription sends an SDP offer or answer to the remote peer.
func (rt *webrtcExternalSignalTransport) SendDescription(ctx context.Context, desc webrtc.SessionDescription) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	b, err := json.Marshal(desc)
	if err != nil {
		return err
	}
	context.LoggerFrom(ctx).Debug("Sending SDP description", "description", string(b))
	err = rt.stream.Send(&v1.StartDataChannelRequest{
		NodeId: rt.NodeID,
		Proto:  rt.TargetProto,
		Dst:    rt.TargetAddr.Addr().String(),
		Port:   uint32(rt.TargetAddr.Port()),
		Answer: string(b),
	})
	if err != nil {
		if status.Code(err) == codes.Canceled {
			return transport.ErrSignalTransportClosed
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
	context.LoggerFrom(ctx).Debug("Sending ICE candidate", "candidate", string(b))
	err = rt.stream.Send(&v1.StartDataChannelRequest{
		NodeId:    rt.NodeID,
		Proto:     rt.TargetProto,
		Dst:       rt.TargetAddr.Addr().String(),
		Port:      uint32(rt.TargetAddr.Port()),
		Candidate: string(b),
	})
	if err != nil {
		if status.Code(err) == codes.Canceled {
			return transport.ErrSignalTransportClosed
		}
		return fmt.Errorf("send ICE candidate: %w", err)
	}
	return nil
}

// Close closes the transport.
func (rt *webrtcExternalSignalTransport) Close() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	select {
	case <-rt.closec:
		return nil
	default:
	}
	close(rt.closec)
	defer rt.cancel()
	if rt.stream == nil {
		// Start wasn't even called yet
		return nil
	}
	return rt.stream.CloseSend()
}

func (rt *webrtcExternalSignalTransport) handleNegotiateStream(ctx context.Context, conn *grpc.ClientConn, stream v1.WebRTC_StartDataChannelClient) {
	log := context.LoggerFrom(ctx)
	defer close(rt.errc)
	defer conn.Close()
	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			log.Error("Failed to receive negotiation message", "error", err.Error())
			rt.errc <- fmt.Errorf("receive negotiation message: %w", err)
			return
		}
		if msg.GetCandidate() != "" {
			// Unmarshal and pass the ICE candidate to the caller.
			log.Debug("Received ICE candidate from peer", "candidate", msg.GetCandidate())
			var candidate webrtc.ICECandidateInit
			err := json.Unmarshal([]byte(msg.GetCandidate()), &candidate)
			if err != nil {
				log.Error("Failed to unmarshal ICE candidate", "error", err.Error())
				rt.errc <- fmt.Errorf("unmarshal ICE candidate: %w", err)
				return
			}
			rt.candidatec <- candidate
		}
	}
}
