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

package transport

import (
	"context"
	"fmt"
	"net"

	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// Dialer is a generic interface for dialing a target address over the given network.
// It resembles the net.Dialer interface.
type Dialer interface {
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

// LeaderDialer is the interface for dialing the current leader.
type LeaderDialer interface {
	// DialLeader opens a gRPC connection to the current leader.
	DialLeader(ctx context.Context) (RPCClientConn, error)
}

// LeaderDialerFunc is a function that implements LeaderDialer.
type LeaderDialerFunc func(ctx context.Context) (RPCClientConn, error)

// DialLeader implements LeaderDialer.
func (f LeaderDialerFunc) DialLeader(ctx context.Context) (RPCClientConn, error) {
	return f(ctx)
}

// NewNoOpLeaderDialer returns a dialer that always returns an error.
func NewNoOpLeaderDialer() LeaderDialer {
	return LeaderDialerFunc(func(ctx context.Context) (RPCClientConn, error) {
		return nil, fmt.Errorf("no-op leader dialer")
	})
}

// NodeDialer is an interface for dialing an arbitrary node. The node ID
// is optional and if empty, implementations can choose the node to dial.
type NodeDialer interface {
	DialNode(ctx context.Context, id types.NodeID) (RPCClientConn, error)
}

// NodeDialerFunc is the function signature for dialing an arbitrary node.
// It is supplied by the mesh during startup. It can be used as an
// alternative to the NodeDialer interface.
type NodeDialerFunc func(ctx context.Context, id types.NodeID) (RPCClientConn, error)

// Dial implements NodeDialer.
func (f NodeDialerFunc) DialNode(ctx context.Context, id types.NodeID) (RPCClientConn, error) {
	return f(ctx, id)
}

// NewNoOpNodeDialer returns a dialer that always returns an error.
func NewNoOpNodeDialer() NodeDialer {
	return NodeDialerFunc(func(ctx context.Context, id types.NodeID) (RPCClientConn, error) {
		return nil, fmt.Errorf("no-op node dialer")
	})
}
