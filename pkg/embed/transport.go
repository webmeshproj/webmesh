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
	"time"

	"github.com/libp2p/go-libp2p"
	p2pconfig "github.com/libp2p/go-libp2p/config"
	p2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/config"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/embed/protocol"
	"github.com/webmeshproj/webmesh/pkg/embed/transport"
	"github.com/webmeshproj/webmesh/pkg/util/logutil"
)

// TransportOptions are options for configuring a libp2p transport.
type TransportOptions struct {
	Config     *config.Config
	Laddrs     []ma.Multiaddr
	Rendezvous string
	LogLevel   string
}

// WithWebmeshTransport returns a libp2p option that configures the transport to use an
// embedded webmesh node.
func WithWebmeshTransport(topts TransportOptions) p2pconfig.Option {
	ctx := context.Background()
	key, err := topts.Config.LoadKey(ctx)
	if err != nil {
		panic(err)
	}
	rtBuilder, rt := transport.New(transport.Options{
		Config:        topts.Config.ShallowCopy(),
		LogLevel:      topts.LogLevel,
		StartTimeout:  time.Second * 30,
		StopTimeout:   time.Second * 30,
		ListenTimeout: time.Second * 30,
		Logger:        logutil.NewLogger(topts.LogLevel),
	})
	opts := []p2pconfig.Option{
		libp2p.ProtocolVersion(protocol.SecurityID),
		libp2p.Transport(rtBuilder),
		libp2p.Identity(key),
		libp2p.AddrsFactory(rt.BroadcastAddrs),
	}
	if len(topts.Laddrs) > 0 {
		// Append our webmesh IDs to the listen addresses.
		webmeshSec := protocol.WithPeerID(key.ID())
		if topts.Rendezvous != "" {
			webmeshSec = protocol.WithPeerIDAndRendezvous(key.ID(), topts.Rendezvous)
		}
		for i, laddr := range topts.Laddrs {
			topts.Laddrs[i] = ma.Join(laddr, webmeshSec)
		}
		opts = append(opts, libp2p.ListenAddrs(topts.Laddrs...))
	}
	return libp2p.ChainOptions(append(opts, libp2p.FallbackDefaults)...)
}

// WithLiteWebmeshTransport returns a libp2p option that configures the transport to use
// the lite webmesh transport.
func WithLiteWebmeshTransport(opts transport.LiteOptions, laddrs ...ma.Multiaddr) p2pconfig.Option {
	// Append an empty webmesh ID to each one
	for i, laddr := range laddrs {
		laddrs[i] = ma.Join(laddr, ma.StringCast("/webmesh/Cg=="))
	}
	if len(laddrs) == 0 {
		// Make sure we have at least one webmesh TCP address
		laddrs = append(laddrs, ma.Join(ma.StringCast("/ip6/::/tcp/0/webmesh/Cg==")))
	}
	// Append a quic address for endpoint negotiation
	transportConstructor, securityConstructor, transport := transport.NewLite(opts)
	chainopts := libp2p.ChainOptions(
		libp2p.ProtocolVersion(protocol.SecurityID),
		libp2p.Security(protocol.SecurityID, securityConstructor),
		libp2p.Transport(transportConstructor),
		libp2p.Transport(p2pquic.NewTransport),
		libp2p.AddrsFactory(transport.BroadcastAddrs),
		libp2p.ListenAddrs(laddrs...),
	)
	return chainopts
}
