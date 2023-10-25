//go:build !wasm

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

// Package libp2p provides webmesh integration with libp2p.
package libp2p

import (
	"net"

	"github.com/libp2p/go-libp2p/core/network"
	mnet "github.com/multiformats/go-multiaddr/net"
)

// NewConnFromStream creates a new net.Conn from a libp2p stream.
func NewConnFromStream(stream network.Stream) net.Conn {
	return &streamConn{stream}
}

type streamConn struct {
	network.Stream
}

func (s *streamConn) LocalAddr() net.Addr {
	addr, _ := mnet.ToNetAddr(s.Stream.Conn().LocalMultiaddr())
	return addr
}

func (s *streamConn) RemoteAddr() net.Addr {
	addr, _ := mnet.ToNetAddr(s.Stream.Conn().RemoteMultiaddr())
	return addr
}
