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
	ma "github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/cmd/config"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/embed/connmgr"
	"github.com/webmeshproj/webmesh/pkg/embed/peerstore"
	"github.com/webmeshproj/webmesh/pkg/embed/protocol"
	"github.com/webmeshproj/webmesh/pkg/embed/security"
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

// WithWebmeshTransport returns a libp2p option that configures the transport to use the embedded node.
func WithWebmeshTransport(topts TransportOptions) p2pconfig.Option {
	ctx := context.Background()
	key, err := topts.Config.LoadKey(ctx)
	if err != nil {
		panic(err)
	}
	log := logutil.NewLogger(topts.LogLevel)
	secBuilder, sec := security.New(key, log.With("component", "sec-manager"))
	rtBuilder, rt := transport.New(transport.Options{
		Config:        topts.Config.ShallowCopy(),
		LogLevel:      topts.LogLevel,
		StartTimeout:  time.Second * 30,
		StopTimeout:   time.Second * 30,
		ListenTimeout: time.Second * 30,
	}, sec)
	opts := []p2pconfig.Option{
		libp2p.ProtocolVersion(security.ID),
		libp2p.Security(security.ID, secBuilder),
		libp2p.Transport(rtBuilder),
		libp2p.Identity(key),
		libp2p.Peerstore(peerstore.New(log.With("component", "peerstore"))),
		libp2p.ConnectionManager(connmgr.New(logutil.NewLogger(topts.LogLevel).With("component", "conn-manager"))),
		libp2p.DisableMetrics(),
	}
	webmeshSec := protocol.WithPeerID(key.ID())
	if topts.Rendezvous != "" {
		webmeshSec = protocol.WithPeerIDAndRendezvous(key.ID(), topts.Rendezvous)
	}
	if len(topts.Laddrs) > 0 {
		// Append our webmesh IDs to the listen addresses.
		for i, laddr := range topts.Laddrs {
			topts.Laddrs[i] = ma.Join(laddr, webmeshSec)
		}
		opts = append(opts, libp2p.ListenAddrs(topts.Laddrs...))
	}
	opts = append(opts, libp2p.AddrsFactory(rt.ConvertAddrs))
	opts = append(opts, libp2p.FallbackDefaults)
	return libp2p.ChainOptions(opts...)
}
