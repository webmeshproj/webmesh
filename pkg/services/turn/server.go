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

// Package turn contains the STUN/TURN server.
package turn

import (
	"fmt"
	"net"
	"strconv"

	"github.com/pion/turn/v2"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/util"
)

// Options contains the options for the TURN server.
type Options struct {
	// PublicIP is the public IP address of the TURN server.
	PublicIP string
	// ListenAddressUDP is the address the TURN server uses for request
	// handling and STUN relays.
	// Defaults to 0.0.0.0.
	ListenAddressUDP string
	// ListenPortUDP is the port the TURN server listens on for UDP requests.
	ListenPortUDP int
	// Realm is the realm used for authentication.
	Realm string
	// PortRange is the range of ports the TURN server will use for relaying.
	PortRange string
}

// Server is a TURN server.
type Server struct {
	*turn.Server
}

// NewServer creates and starts a new TURN server.
func NewServer(o *Options) (*Server, error) {
	startPort, endPort, err := util.ParsePortRange(o.PortRange)
	if err != nil {
		return nil, fmt.Errorf("failed to parse port range: %w", err)
	}
	if o.ListenPortUDP == 0 {
		return nil, fmt.Errorf("listen port UDP must be set")
	}
	if o.ListenAddressUDP == "" {
		o.ListenAddressUDP = "0.0.0.0"
	}
	udpListenAddr := net.JoinHostPort(o.ListenAddressUDP, strconv.Itoa(o.ListenPortUDP))
	udpConn, err := net.ListenPacket("udp4", udpListenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on UDP: %w", err)
	}
	log := slog.Default().With("component", "turn-server")
	log.Info("Listening for STUN requests", slog.String("listen-addr", udpListenAddr))
	logWrapper := &stunLogger{
		PacketConn: udpConn,
		log:        log.With("channel", "stun"),
	}
	s, err := turn.NewServer(turn.ServerConfig{
		Realm:         o.Realm,
		LoggerFactory: util.NewSTUNLoggerFactory(log.With("server", "turn")),
		// Set AuthHandler callback
		// This is called every time a user tries to authenticate with the TURN server
		// Return the key for that user, or false when no user is found
		AuthHandler: func(username string, realm string, srcAddr net.Addr) ([]byte, bool) {
			// TODO: Negotiate one-time credentials with the client
			return nil, true
		},
		// PacketConnConfigs is a list of UDP Listeners and the configuration around them
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: &campFireManager{PacketConn: logWrapper, log: log.With("channel", "relay")},
				RelayAddressGenerator: &turn.RelayAddressGeneratorPortRange{
					RelayAddress: net.ParseIP(o.PublicIP),
					Address:      o.ListenAddressUDP,
					MinPort:      uint16(startPort),
					MaxPort:      uint16(endPort),
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create TURN server: %w", err)
	}
	return &Server{s}, nil
}
