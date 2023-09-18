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

package wgtransport

import (
	"errors"
	"net"

	"github.com/libp2p/go-libp2p/core/transport"
	ma "github.com/multiformats/go-multiaddr"
	mnet "github.com/multiformats/go-multiaddr/net"

	wmproto "github.com/webmeshproj/webmesh/pkg/libp2p/protocol"
)

// Listener wraps a basic listener to be upgraded and injects the transport
// into incoming connections.
type Listener struct {
	mnet.Listener
	rt    *Transport
	conns chan *Conn
	donec chan struct{}
}

// Accept waits for and returns the next connection to the listener.
func (ln *Listener) Accept() (mnet.Conn, error) {
	select {
	case c := <-ln.conns:
		return c, nil
	case <-ln.donec:
		return nil, transport.ErrListenerClosed
	}
}

func (ln *Listener) Multiaddr() ma.Multiaddr {
	return wmproto.Encapsulate(ln.Listener.Multiaddr(), ln.rt.peerID)
}

func (ln *Listener) handleIncoming() {
	defer close(ln.donec)
	for {
		c, err := ln.Listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			ln.rt.log.Error("Failed to accept connection", "error", err.Error())
			return
		}
		ln.conns <- ln.rt.WrapConn(c)
	}
}
