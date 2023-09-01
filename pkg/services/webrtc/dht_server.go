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

package webrtc

import (
	"fmt"
	"time"

	"github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/net/transport/libp2p"
	"github.com/webmeshproj/webmesh/pkg/services"
)

// DHTOptions are options for the DHTServer.
type DHTOptions struct {
	// RendevousStrings is a map of peer IDs to rendezvous strings
	// for allowing signaling through libp2p.
	RendezvousStrings map[string]string
	// BootstrapServers is a list of bootstrap servers to use for the DHT.
	// If empty or nil, the default bootstrap servers will be used.
	BootstrapServers []multiaddr.Multiaddr
	// LocalAddrs is a list of local addresses to announce to the discovery service.
	// If empty, the default local addresses will be used.
	LocalAddrs []multiaddr.Multiaddr
	// AnnounceTTL is the TTL for each announcement.
	AnnounceTTL time.Duration
	// STUNServers is a list of STUN servers to use for NAT traversal.
	// If empty, the default STUN servers will be used.
	STUNServers []string
	// WireGuardPort is the port to use for connections targeting WireGuard.
	WireGuardPort int
}

// Ensure DHTServer implements services.MeshServer.
var _ services.MeshServer = (*DHTServer)(nil)

// NewDHTServer returns a new DHTServer.
func NewDHTServer(opts DHTOptions) *DHTServer {
	return &DHTServer{DHTOptions: opts}
}

// DHTServer is the webmesh DHT service.
type DHTServer struct {
	DHTOptions
	announcer *libp2p.DataChannelAnnouncer
}

// ListenAndServe starts the server and blocks until the server exits.
func (srv *DHTServer) ListenAndServe() error {
	if len(srv.STUNServers) == 0 {
		srv.STUNServers = DefaultSTUNServers
	}
	ctx := context.Background()
	log := context.LoggerFrom(ctx).With("service", "dht-webrtc")
	log.Info("Starting DHT WebRTC signaling server")
	announcer, err := libp2p.NewDataChannelAnnouncer(context.WithLogger(ctx, log), libp2p.DataChannelAnnounceOptions{
		RendezvousStrings:  srv.RendezvousStrings,
		BootstrapPeers:     srv.BootstrapServers,
		AnnounceTTL:        time.Minute,
		LocalAddrs:         srv.LocalAddrs,
		STUNServers:        srv.STUNServers,
		DataChannelTimeout: time.Minute,
		WireGuardPort:      srv.WireGuardPort,
	})
	if err != nil {
		return fmt.Errorf("failed to create data channel announcer: %w", err)
	}
	srv.announcer = announcer
	return nil
}

// Shutdown attempts to stops the server gracefully.
func (srv *DHTServer) Shutdown(ctx context.Context) error {
	return srv.announcer.Close()
}
