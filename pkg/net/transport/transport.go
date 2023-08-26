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

// Package transport provides a simple interface for sending and receiving raft
// messages between nodes.
package transport

import (
	"context"
	"net/netip"

	"github.com/hashicorp/raft"
	"google.golang.org/grpc"
)

// RaftTransport defines the methods needed for raft consensus to function
// in a webmesh cluster.
type RaftTransport interface {
	raft.Transport
	LeaderDialer

	// AddrPort returns the address and port the transport is listening on.
	AddrPort() netip.AddrPort
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
