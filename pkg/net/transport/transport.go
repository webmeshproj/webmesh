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
	"net/netip"

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
)

// RoundTripper is a generic interface for executing a request and returning
// a response.
type RoundTripper[REQ, RESP any] interface {
	RoundTrip(ctx context.Context, req *REQ) (*RESP, error)
}

// RoundTripperFunc is a function that implements RoundTripper.
type RoundTripperFunc[REQ, RESP any] func(ctx context.Context, req *REQ) (*RESP, error)

// RoundTrip implements RoundTripper.
func (f RoundTripperFunc[REQ, RESP]) RoundTrip(ctx context.Context, req *REQ) (*RESP, error) {
	return f(ctx, req)
}

// JoinRoundTripper is the interface for joining a cluster.
type JoinRoundTripper = RoundTripper[v1.JoinRequest, v1.JoinResponse]

// JoinServer is the interface for handling requests to join a cluster.
type JoinServer interface {
	// Join is executed when a request to join a cluster is received.
	Join(ctx context.Context, req *v1.JoinRequest) (*v1.JoinResponse, error)
}

// JoinServerFunc is a function that implements JoinServer.
type JoinServerFunc func(ctx context.Context, req *v1.JoinRequest) (*v1.JoinResponse, error)

// Join implements JoinServer.
func (f JoinServerFunc) Join(ctx context.Context, req *v1.JoinRequest) (*v1.JoinResponse, error) {
	return f(ctx, req)
}

// ErrAlreadyBootstrapped is returned when a node believes the cluster to be
// already bootstrapped.
var ErrAlreadyBootstrapped = raft.ErrCantBootstrap

// BootstrapTransport is the interface for dialing other peers to bootstrap
// a new mesh.
type BootstrapTransport interface {
	// LeaderElect should perform an initial leader election. It returns
	// true is this node was elected leader, or otherwise a JoinRoundTripper
	// for contacting the elected leader. If one or more nodes believe
	// the cluster to be already bootstrapped, then ErrAlreadyBootstrapped
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
// testing and when no bootstrap transport is needed.
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
	Dial(ctx context.Context, id string) (*grpc.ClientConn, error)
}

// NodeDialerFunc is the function signature for dialing an arbitrary node.
// It is supplied by the mesh during startup. It can be used as an
// alternative to the NodeDialer interface.
type NodeDialerFunc func(ctx context.Context, id string) (*grpc.ClientConn, error)

// Dial implements NodeDialer.
func (f NodeDialerFunc) Dial(ctx context.Context, id string) (*grpc.ClientConn, error) {
	return f(ctx, id)
}
