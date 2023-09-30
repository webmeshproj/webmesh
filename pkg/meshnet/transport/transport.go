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
	"net"
	"net/netip"

	"github.com/hashicorp/raft"
	"github.com/pion/webrtc/v3"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// Dialer is a generic interface for dialing a target address over the given network.
// It resembles the net.Dialer interface.
type Dialer interface {
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

// Resolver is the interface for resolving node addresses. Implementations
// can be pre-baked for specialized cases, such as resolving node addresses
// by a specific feature. The returned type is an AddrPort to support
// resolvers that need to return port numbers.
type Resolver[T any] interface {
	// Resolve resolves the addresses for the given lookup parameters.
	Resolve(ctx context.Context, lookup T) ([]netip.AddrPort, error)
}

// ResolverFunc is a function that implements Resolver.
type ResolverFunc[T any] func(ctx context.Context, lookup T) ([]netip.AddrPort, error)

// Resolve implements Resolver.
func (f ResolverFunc[T]) Resolve(ctx context.Context, lookup T) ([]netip.AddrPort, error) {
	return f(ctx, lookup)
}

// NodeIDResolver is a resolver that resolves node addresses by node ID.
type NodeIDResolver = Resolver[types.NodeID]

// NodeIDResolverFunc is a function that implements NodeIDResolver.
type NodeIDResolverFunc = ResolverFunc[types.NodeID]

// FeatureResolver is a resolver that resolves node addresses by feature.
type FeatureResolver = Resolver[v1.Feature]

// FeatureResolverFunc is a function that implements FeatureResolver.
type FeatureResolverFunc = ResolverFunc[v1.Feature]

// RoundTripper is a generic interface for executing a request and returning
// a response.
type RoundTripper[REQ, RESP any] interface {
	io.Closer

	RoundTrip(ctx context.Context, req *REQ) (*RESP, error)
}

// RoundTripperFunc is a function that implements RoundTripper.
type RoundTripperFunc[REQ, RESP any] func(ctx context.Context, req *REQ) (*RESP, error)

// RoundTrip implements RoundTripper.
func (f RoundTripperFunc[REQ, RESP]) RoundTrip(ctx context.Context, req *REQ) (*RESP, error) {
	return f(ctx, req)
}

// RoundTrip implements RoundTripper.
func (f RoundTripperFunc[REQ, RESP]) Close() error {
	return nil
}

// JoinRoundTripper is the interface for joining a cluster.
type JoinRoundTripper = RoundTripper[v1.JoinRequest, v1.JoinResponse]

// JoinRoundTripperFunc is a function that implements JoinRoundTripper.
type JoinRoundTripperFunc = RoundTripperFunc[v1.JoinRequest, v1.JoinResponse]

// UnaryServer is the interface for handling unary requests.
type UnaryServer[REQ, RESP any] interface {
	// Serve is executed when a unary request is received.
	Serve(ctx context.Context, req *REQ) (*RESP, error)
}

// UnaryServerFunc is a function that implements UnaryServer.
type UnaryServerFunc[REQ, RESP any] func(ctx context.Context, req *REQ) (*RESP, error)

// Serve implements UnaryServer.
func (f UnaryServerFunc[REQ, RESP]) Serve(ctx context.Context, req *REQ) (*RESP, error) {
	return f(ctx, req)
}

// JoinServer is the interface for handling requests to join a cluster.
type JoinServer = UnaryServer[v1.JoinRequest, v1.JoinResponse]

// JoinServerFunc is a function that implements JoinServer.
type JoinServerFunc = UnaryServerFunc[v1.JoinRequest, v1.JoinResponse]

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

// LeaderDialer is the interface for dialing the current leader.
type LeaderDialer interface {
	// DialLeader opens a gRPC connection to the current leader.
	DialLeader(ctx context.Context) (*grpc.ClientConn, error)
}

// LeaderDialerFunc is a function that implements LeaderDialer.
type LeaderDialerFunc func(ctx context.Context) (*grpc.ClientConn, error)

// DialLeader implements LeaderDialer.
func (f LeaderDialerFunc) DialLeader(ctx context.Context) (*grpc.ClientConn, error) {
	return f(ctx)
}

// NodeDialer is an interface for dialing an arbitrary node. The node ID
// is optional and if empty, implementations can choose the node to dial.
type NodeDialer interface {
	DialNode(ctx context.Context, id types.NodeID) (*grpc.ClientConn, error)
}

// NodeDialerFunc is the function signature for dialing an arbitrary node.
// It is supplied by the mesh during startup. It can be used as an
// alternative to the NodeDialer interface.
type NodeDialerFunc func(ctx context.Context, id types.NodeID) (*grpc.ClientConn, error)

// Dial implements NodeDialer.
func (f NodeDialerFunc) DialNode(ctx context.Context, id types.NodeID) (*grpc.ClientConn, error) {
	return f(ctx, id)
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
