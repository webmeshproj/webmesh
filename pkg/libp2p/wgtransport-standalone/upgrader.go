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
	"fmt"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/transport"
	mnet "github.com/multiformats/go-multiaddr/net"

	"github.com/webmeshproj/webmesh/pkg/context"
	wmproto "github.com/webmeshproj/webmesh/pkg/libp2p/protocol"
)

// Ensure we satisfy the interface
var _ transport.Upgrader = (*Upgrader)(nil)

// Upgrader is the webmesh upgrader. It checks for a magic header on incoming connections
// and upgrades them to a full webmesh connection. Otherwise it passes them to the default
// libp2p upgrader.
type Upgrader struct {
	rt *Transport
}

// newUpgrader creates a new upgrader.
func newUpgrader(rt *Transport) *Upgrader {
	return &Upgrader{
		rt: rt,
	}
}

// UpgradeListener upgrades the passed multiaddr-net listener into a full libp2p-transport listener.
func (u *Upgrader) UpgradeListener(t transport.Transport, ln mnet.Listener) transport.Listener {
	return upgradeListener(ln, u)
}

// Upgrade upgrades the multiaddr/net connection into a full libp2p-transport connection. It looks for a
// magic header on the connection and upgrades it to a full webmesh connection. Otherwise it passes it
// to the default libp2p upgrader.
func (u *Upgrader) Upgrade(ctx context.Context, t transport.Transport, maconn mnet.Conn, dir network.Direction, p peer.ID, scope network.ConnManagementScope) (transport.CapableConn, error) {
	c, err := u.upgradeConn(ctx, maconn, dir, p, scope)
	if err != nil {
		defer scope.Done()
		return nil, err
	}
	err = u.rt.host.Peerstore().AddProtocols(p, wmproto.SecurityID)
	if err != nil {
		defer scope.Done()
		return nil, err
	}
	return c, nil
}

// upgradeConn wraps a connection in webmesh security and muxing.
func (u *Upgrader) upgradeConn(ctx context.Context, maconn mnet.Conn, dir network.Direction, p peer.ID, scope network.ConnManagementScope) (transport.CapableConn, error) {
	// Upgrade the connection
	switch dir {
	case network.DirInbound:
		sc, err := u.rt.sec.SecureInbound(ctx, maconn, p)
		if err != nil {
			return nil, err
		}
		return &CapableConn{
			sc:     sc.(*SecureConn),
			rt:     u.rt,
			scope:  scope,
			lmaddr: wmproto.Encapsulate(maconn.LocalMultiaddr()),
			rmaddr: wmproto.Encapsulate(maconn.RemoteMultiaddr()),
		}, nil
	case network.DirOutbound:
		sc, err := u.rt.sec.SecureOutbound(ctx, maconn, p)
		if err != nil {
			return nil, err
		}
		return &CapableConn{
			sc:     sc.(*SecureConn),
			rt:     u.rt,
			scope:  scope,
			lmaddr: wmproto.Encapsulate(maconn.LocalMultiaddr()),
			rmaddr: wmproto.Encapsulate(maconn.RemoteMultiaddr()),
		}, nil
	default:
		return nil, fmt.Errorf("invalid upgrade direction: %v", dir)
	}
}
