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

// Package tcp provides TCP based transports.
package tcp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/hashicorp/raft"

	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
)

// RaftTransportOptions are options for the TCP transport.
type RaftTransportOptions struct {
	// Addr is the address to listen on.
	Addr string
	// MaxPool is the maximum number of connections to pool.
	MaxPool int
	// Timeout is the timeout for dialing a connection.
	Timeout time.Duration
}

// NewRaftTransport creates a new TCP transport listening on the given address.
func NewRaftTransport(leaderDialer transport.LeaderDialer, opts RaftTransportOptions) (transport.RaftTransport, error) {
	sl, err := newTCPStreamLayer(opts.Addr)
	if err != nil {
		return nil, fmt.Errorf("create TCP stream layer: %w", err)
	}
	t := raft.NewNetworkTransport(sl, opts.MaxPool, opts.Timeout, nil)
	if err != nil {
		return nil, fmt.Errorf("create TCP transport: %w", err)
	}
	laddr := sl.AddrPort()
	if err != nil {
		defer t.Close()
		return nil, fmt.Errorf("parse address: %w", err)
	}
	return &RaftTransport{NetworkTransport: t, LeaderDialer: leaderDialer, laddr: laddr}, nil
}

// RaftTransport is a transport that uses raw TCP.
type RaftTransport struct {
	*raft.NetworkTransport
	transport.LeaderDialer
	laddr netip.AddrPort
}

func (t *RaftTransport) AddrPort() netip.AddrPort {
	return t.laddr
}

// TCPTransport is a transport that uses raw TCP.
type tcpStreamLayer struct {
	net.Listener
	*net.Dialer
}

func newTCPStreamLayer(addr string) (*tcpStreamLayer, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	return &tcpStreamLayer{
		Listener: ln,
		Dialer:   &net.Dialer{},
	}, nil
}

func (t *tcpStreamLayer) AddrPort() netip.AddrPort {
	return t.Listener.Addr().(*net.TCPAddr).AddrPort()
}

// Dial is used to create a new outgoing connection
func (t *tcpStreamLayer) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return t.DialContext(ctx, "tcp", string(address))
}
