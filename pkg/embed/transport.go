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

	"github.com/libp2p/go-libp2p"
	p2pconfig "github.com/libp2p/go-libp2p/config"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/cmd/config"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/embed/security"
	"github.com/webmeshproj/webmesh/pkg/embed/transport"
)

// TransportOptions are options for configuring a libp2p transport.
type TransportOptions struct {
	Config   *config.Config
	Laddrs   []ma.Multiaddr
	LogLevel string
}

// WithWebmeshTransport returns a libp2p option that configures the transport to use the embedded node.
func WithWebmeshTransport(topts TransportOptions) p2pconfig.Option {
	ctx := context.Background()
	key, err := topts.Config.LoadKey(ctx)
	if err != nil {
		panic(err)
	}
	builder, sec := security.New()
	opts := []p2pconfig.Option{
		libp2p.Identity(key),
		libp2p.Security(security.SecurityProtocol, builder),
		libp2p.Transport(transport.New(transport.Options{
			Config:        topts.Config.ShallowCopy(),
			LogLevel:      topts.LogLevel,
			StartTimeout:  time.Second * 30,
			StopTimeout:   time.Second * 30,
			ListenTimeout: time.Second * 30,
		}, sec)),
	}
	webmeshSec := ma.StringCast(fmt.Sprintf("%s/%s", security.SecurityProtocol, key.ID()))
	if topts.Config.Discovery.Announce || topts.Config.Discovery.Discover {
		webmeshSec = ma.StringCast(fmt.Sprintf("%s/%s", webmeshSec.String(), topts.Config.Discovery.PSK))
	}
	if len(topts.Laddrs) > 0 {
		// Append our webmesh IDs to the listen addresses.
		for i, laddr := range topts.Laddrs {
			topts.Laddrs[i] = ma.Join(laddr, webmeshSec)
		}
		opts = append(opts, libp2p.ListenAddrs(topts.Laddrs...))
	}
	return libp2p.ChainOptions(opts...)
}
