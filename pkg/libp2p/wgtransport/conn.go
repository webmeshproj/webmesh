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
	"log/slog"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	mnet "github.com/multiformats/go-multiaddr/net"

	"github.com/webmeshproj/webmesh/pkg/context"
	wmcrypto "github.com/webmeshproj/webmesh/pkg/crypto"
	wmproto "github.com/webmeshproj/webmesh/pkg/libp2p/protocol"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
)

// Conn wraps the basic net.Conn with a reference back to the underlying transport.
type Conn struct {
	mnet.Conn
	rt     *Transport
	lkey   wmcrypto.PrivateKey
	lpeer  peer.ID
	iface  wireguard.Interface
	rmaddr ma.Multiaddr
	eps    []string
	log    *slog.Logger
}

func (w *Conn) LocalMultiaddr() ma.Multiaddr {
	return wmproto.Encapsulate(w.Conn.LocalMultiaddr(), w.lpeer)
}

func (w *Conn) RemoteMultiaddr() ma.Multiaddr {
	return w.rmaddr
}

// Context returns a context that contains the logger tied
// to this connection
func (w *Conn) Context() context.Context {
	return context.WithLogger(context.Background(), w.log)
}
