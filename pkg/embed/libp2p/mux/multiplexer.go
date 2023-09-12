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

// Package multiplexer implements an IPv6 allocation based multiplexer
// for libp2p connections.
package multiplexer

import (
	"context"
	"net"
	"sync/atomic"

	"github.com/libp2p/go-libp2p/core/network"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/embed/libp2p/util"
)

// Ensure we implement the interface
var _ network.Multiplexer = (*Multiplexer)(nil)
var _ network.MuxedConn = (*Conn)(nil)
var _ network.MuxedStream = (*Stream)(nil)

// Multiplexer is a multiplexer for libp2p connections.
type Multiplexer struct {
	key crypto.PrivateKey
}

// NewConn constructs a new connection
func (m *Multiplexer) NewConn(c net.Conn, isServer bool, scope network.PeerScope) (network.MuxedConn, error) {
	key, err := scope.Peer().ExtractPublicKey()
	if err != nil {
		return nil, err
	}
	wmkey, err := util.ToWebmeshPublicKey(key)
	if err != nil {
		return nil, err
	}
	return &Conn{
		Conn:     c,
		localKey: m.key,
		peerKey:  wmkey,
		isServer: isServer,
	}, nil
}

// Conn is a connection that can be multiplexed
type Conn struct {
	net.Conn
	open     atomic.Bool
	localKey crypto.PrivateKey
	peerKey  crypto.PublicKey
	isServer bool
}

// IsClosed returns whether a connection is fully closed, so it can
// be garbage collected.
func (c *Conn) IsClosed() bool {
	return !c.open.Load()
}

// OpenStream creates a new stream.
func (c *Conn) OpenStream(context.Context) (network.MuxedStream, error) {
	return nil, nil
}

// AcceptStream accepts a stream opened by the other side.
func (c *Conn) AcceptStream() (network.MuxedStream, error) {
	return nil, nil
}

// Stream is a multiplexed stream.
type Stream struct {
	net.Conn
}

// CloseRead closes the stream for reading but leaves it open for
// writing.
//
// When CloseRead is called, all in-progress Read calls are interrupted with a non-EOF error and
// no further calls to Read will succeed.
//
// The handling of new incoming data on the stream after calling this function is implementation defined.
//
// CloseRead does not free the stream, users must still call Close or
// Reset.
func (s *Stream) CloseRead() error {
	return nil
}

// CloseWrite closes the stream for writing but leaves it open for
// reading.
//
// CloseWrite does not free the stream, users must still call Close or
// Reset.
func (s *Stream) CloseWrite() error {
	return nil
}

// Reset closes both ends of the stream. Use this to tell the remote
// side to hang up and go away.
func (s *Stream) Reset() error {
	return nil
}
