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

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/transport"
	ma "github.com/multiformats/go-multiaddr"
	mnet "github.com/multiformats/go-multiaddr/net"

	"github.com/webmeshproj/webmesh/pkg/context"
	wmproto "github.com/webmeshproj/webmesh/pkg/libp2p/protocol"
)

// WebmeshListener wraps a basic listener to be upgraded and injects the transport
// into incoming connections.
type WebmeshListener struct {
	ln    mnet.Listener
	tu    *Upgrader
	cc    chan transport.CapableConn
	donec chan struct{}
	log   *slog.Logger
}

func upgradeListener(ln mnet.Listener, tu *Upgrader) transport.Listener {
	wln := &WebmeshListener{
		ln:    ln,
		tu:    tu,
		cc:    make(chan transport.CapableConn, 100),
		donec: make(chan struct{}),
	}
	go wln.handleIncoming()
	return wln
}

// Accept waits for and returns the next connection to the listener.
func (ln *WebmeshListener) Accept() (transport.CapableConn, error) {
	select {
	case <-ln.donec:
		return nil, transport.ErrListenerClosed
	case c, ok := <-ln.cc:
		if !ok {
			return nil, transport.ErrListenerClosed
		}
		if c == nil {
			return nil, errors.New("received nil connection")
		}
		return c, nil
	}
}

// Addr returns the local listener address.
func (ln *WebmeshListener) Addr() net.Addr {
	return ln.ln.Addr()
}

// Multiaddr encapsulates the listener with the webmesh protocol.
func (ln *WebmeshListener) Multiaddr() ma.Multiaddr {
	return wmproto.Encapsulate(ln.ln.Multiaddr(), ln.tu.rt.peerID)
}

// Close closes the listener.
func (ln *WebmeshListener) Close() error {
	return ln.ln.Close()
}

// handleIncoming handles incoming connections on the listener.
func (ln *WebmeshListener) handleIncoming() {
	defer close(ln.cc)
	defer close(ln.donec)
	for {
		c, err := ln.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			ln.log.Error("Failed to accept connection", "error", err.Error())
		}
		ln.log.Debug("Accepted new connection", "remote", c.RemoteMultiaddr().String())
		ctx := context.WithLogger(context.Background(), ln.log)
		connScope, err := ln.tu.rt.rcmgr.OpenConnection(network.DirInbound, false, c.RemoteMultiaddr())
		if err != nil {
			ln.log.Error("Failed to open connection", "error", err.Error())
			continue
		}
		cc, err := ln.tu.Upgrade(ctx, ln.tu.rt, c, network.DirInbound, "", connScope)
		if err != nil {
			ln.log.Error("Failed to upgrade connection", "error", err.Error())
			continue
		}
		ln.cc <- cc
	}
}
