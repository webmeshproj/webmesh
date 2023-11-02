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

// Package transport defines the interfaces needed for various mesh operations.
package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/hashicorp/raft"
	"github.com/pion/webrtc/v3"
	"google.golang.org/grpc"
)

// RPCClientConn is a grpc.ClientConnInterface that can be closed.
type RPCClientConn interface {
	grpc.ClientConnInterface
	io.Closer
}

// RPCTransport is the interface for opening a gRPC connection to a remote peer.
// the ID is optional and may be ignored by implementations.
type RPCTransport interface {
	// Dial opens a gRPC client connection to the remote address. Implementations
	// may choose to ignore the id or address.
	Dial(ctx context.Context, id, address string) (RPCClientConn, error)
}

// BootstrapTransport is the interface for dialing other peers to bootstrap
// a new mesh.
type BootstrapTransport interface {
	// LeaderElect should perform an initial leader election. It returns
	// true is this node was elected leader, or otherwise a JoinRoundTripper
	// for contacting the elected leader. If one or more nodes believe
	// the cluster to be already bootstrapped, then storage.ErrAlreadyBootstrapped
	// should be returned with an optional JoinRoundTripper to nodes who are
	// already bootstrapped.
	LeaderElect(ctx context.Context) (isLeader bool, rt JoinRoundTripper, err error)
}

// BootstrapTransportFunc is a function that implements BootstrapTransport.
type BootstrapTransportFunc func(ctx context.Context) (isLeader bool, rt JoinRoundTripper, err error)

// LeaderElect implements BootstrapTransport.
func (f BootstrapTransportFunc) LeaderElect(ctx context.Context) (isLeader bool, rt JoinRoundTripper, err error) {
	return f(ctx)
}

// NewNullBootstrapTransport returns a BootstrapTransport that always returns
// true for LeaderElect and nil for JoinRoundTripper. This is useful for
// testing or when otherwise no bootstrap transport is needed.
func NewNullBootstrapTransport() BootstrapTransport {
	return BootstrapTransportFunc(func(ctx context.Context) (isLeader bool, rt JoinRoundTripper, err error) {
		return true, nil, nil
	})
}

// RaftTransport defines the methods needed for raft consensus to function
// in a webmesh cluster.
type RaftTransport interface {
	raft.Transport
	LeaderDialer

	// AddrPort returns the address and port the transport is listening on.
	AddrPort() netip.AddrPort

	// Close closes the transport.
	Close() error
}

// ErrSignalTransportClosed is returned when a signal transport is closed
// by either side of the connection.
var ErrSignalTransportClosed = fmt.Errorf("signal transport closed")

// IsSignalTransportClosed returns true if the given error is
// ErrSignalTransportClosed.
func IsSignalTransportClosed(err error) bool {
	return errors.Is(err, ErrSignalTransportClosed)
}

// WebRTCSignalTransport is the transport interface for providing WebRTC signaling between
// mesh nodes.
type WebRTCSignalTransport interface {
	// Start starts the transport. This will not return until a remote peer
	// has provided a session description.
	Start(ctx context.Context) error
	// TURNServers returns a list of TURN servers configured for the transport.
	TURNServers() []webrtc.ICEServer
	// SendDescription sends an SDP description to the remote peer.
	SendDescription(ctx context.Context, desc webrtc.SessionDescription) error
	// SendCandidate sends an ICE candidate to the remote peer.
	SendCandidate(ctx context.Context, candidate webrtc.ICECandidateInit) error
	// Candidates returns a channel of ICE candidates received from the remote peer.
	Candidates() <-chan webrtc.ICECandidateInit
	// RemoteDescription returns the SDP description received from the remote peer.
	RemoteDescription() webrtc.SessionDescription
	// Error returns a channel that receives any error encountered during signaling.
	// This channel will be closed when the transport is closed.
	Error() <-chan error
	// Close closes the transport.
	Close() error
}
