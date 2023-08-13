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
	"log/slog"
	"net"

	"github.com/pion/turn/v2"

	"github.com/webmeshproj/webmesh/pkg/util"
)

// Options contains the options for the TURN server.
type Options struct {
	// PublicIP is the public IP address of the TURN server. This is used for relaying.
	PublicIP string
	// RelayAddressUDP is the binding address the TURN server uses for request handling and STUN relays.
	// Defaults to 0.0.0.0.
	RelayAddressUDP string
	// ListenUDP is the address the TURN server listens on for UDP requests.
	ListenUDP string
	// Realm is the realm used for authentication.
	Realm string
	// PortRange is the range of ports the TURN server will use for relaying.
	PortRange string
	// EnableCampfire enables relaying campfire packets.
	EnableCampfire bool
}

// Server is a TURN server.
type Server struct {
	*turn.Server
	conn net.PacketConn
}

// NewServer creates and starts a new TURN server.
func NewServer(o *Options) (*Server, error) {
	if o.PortRange == "" {
		o.PortRange = "49152-65535"
	}
	startPort, endPort, err := util.ParsePortRange(o.PortRange)
	if err != nil {
		return nil, fmt.Errorf("failed to parse port range: %w", err)
	}
	if o.ListenUDP == "" {
		return nil, fmt.Errorf("listen port UDP must be set")
	}
	if o.RelayAddressUDP == "" {
		o.RelayAddressUDP = "0.0.0.0"
	}
	udpConn, err := net.ListenPacket("udp", o.ListenUDP)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on UDP: %w", err)
	}
	log := slog.Default().With("component", "turn-server")
	log.Info("Listening for STUN requests", slog.String("listen-addr", o.ListenUDP))
	var pktConn net.PacketConn
	pktConn = &stunLogger{
		PacketConn: udpConn,
		log:        log.With("channel", "stun"),
	}
	if o.EnableCampfire {
		log.Info("Enabling campfire protocol extensions")
		pktConn = NewCampFireManager(pktConn, log.With("channel", "campfire"))
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
				PacketConn: pktConn,
				RelayAddressGenerator: &turn.RelayAddressGeneratorPortRange{
					RelayAddress: net.ParseIP(o.PublicIP),
					Address:      o.RelayAddressUDP,
					MinPort:      uint16(startPort),
					MaxPort:      uint16(endPort),
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create TURN server: %w", err)
	}
	return &Server{Server: s, conn: pktConn}, nil
}

// ListenPort returns the port the TURN server is listening on.
func (s *Server) ListenPort() int {
	return s.conn.LocalAddr().(*net.UDPAddr).Port
}
