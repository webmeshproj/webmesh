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

package embed

import (
	"fmt"
	"time"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/config"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	wmconfig "github.com/webmeshproj/webmesh/pkg/config"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/logging"
	p2pproto "github.com/webmeshproj/webmesh/pkg/meshnet/transport/libp2p/embedded/protocol"
	p2ptransport "github.com/webmeshproj/webmesh/pkg/meshnet/transport/libp2p/embedded/transport"
)

// TransportOptions are options for configuring a libp2p transport.
type TransportOptions struct {
	Config     *wmconfig.Config
	Laddrs     []ma.Multiaddr
	Rendezvous string
	LogLevel   string
	LogFormat  string
}

// WithWebmeshTransport returns a libp2p option that configures the transport to use an
// embedded webmesh node.
func WithWebmeshTransport(topts TransportOptions) config.Option {
	ctx := context.Background()
	key, err := topts.Config.WireGuard.LoadKey(ctx)
	if err != nil {
		panic(err)
	}
	rtBuilder, rt := p2ptransport.New(p2ptransport.Options{
		Config:        topts.Config.ShallowCopy(),
		LogLevel:      topts.LogLevel,
		StartTimeout:  time.Second * 30,
		StopTimeout:   time.Second * 30,
		ListenTimeout: time.Second * 30,
		Logger:        logging.NewLogger(topts.LogLevel, topts.LogFormat),
	})
	opts := []config.Option{
		libp2p.ProtocolVersion(p2pproto.SecurityID),
		libp2p.Transport(rtBuilder),
		libp2p.Identity(key.AsIdentity()),
		libp2p.AddrsFactory(rt.BroadcastAddrs),
	}
	if len(topts.Laddrs) > 0 {
		id, err := peer.IDFromPrivateKey(key.AsIdentity())
		if err != nil {
			panic(fmt.Errorf("failed to get peer ID from private key: %w", err))
		}
		// Append our webmesh IDs to the listen addresses.
		webmeshSec := p2pproto.WithPeerID(id)
		if topts.Rendezvous != "" {
			webmeshSec = p2pproto.WithPeerIDAndRendezvous(id, topts.Rendezvous)
		}
		for i, laddr := range topts.Laddrs {
			topts.Laddrs[i] = ma.Join(laddr, webmeshSec)
		}
		opts = append(opts, libp2p.ListenAddrs(topts.Laddrs...))
	}
	return libp2p.ChainOptions(append(opts, libp2p.DefaultTransports)...)
}
