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
	"log/slog"
	"net"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/transport"
	ma "github.com/multiformats/go-multiaddr"
	mnet "github.com/multiformats/go-multiaddr/net"

	wmcrypto "github.com/webmeshproj/webmesh/pkg/crypto"
	wmproto "github.com/webmeshproj/webmesh/pkg/libp2p/protocol"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
)

// WebmeshConn wraps the basic net.Conn with a reference back to the underlying transport.
type WebmeshConn struct {
	mnet.Conn
	lkey  wmcrypto.PrivateKey
	lpeer peer.ID
	iface wireguard.Interface
	eps   []string
	log   *slog.Logger
}

func (w *WebmeshConn) LocalMultiaddr() ma.Multiaddr {
	return wmproto.Encapsulate(w.Conn.LocalMultiaddr())
}

func (w *WebmeshConn) RemoteMultiaddr() ma.Multiaddr {
	return wmproto.Encapsulate(w.Conn.RemoteMultiaddr())
}

// WebmeshListener wraps a basic listener to be upgraded and injects the transport
// into incoming connections.
type WebmeshListener struct {
	mnet.Listener
	rt *Transport
}

// Accept waits for and returns the next connection to the listener.
func (ln *WebmeshListener) Accept() (mnet.Conn, error) {
	c, err := ln.Listener.Accept()
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return nil, transport.ErrListenerClosed
		}
		ln.rt.log.Error("Failed to accept connection", "error", err.Error())
		return nil, err
	}
	wc := ln.rt.WrapConn(c)
	return wc, nil
}

func (ln *WebmeshListener) Multiaddr() ma.Multiaddr {
	return wmproto.Encapsulate(ln.Listener.Multiaddr())
}
