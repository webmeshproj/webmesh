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

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/logging"
	netutil "github.com/webmeshproj/webmesh/pkg/net/util"
)

// DefaultPortRange is the default port range for the TURN server.
const DefaultPortRange = "49152-65535"

// DefaultListenAddress is the default listen address for the TURN server.
const DefaultListenAddress = "[::]:3478"

// DefaultRelayAddress is the default relay address for the TURN server.
const DefaultRelayAddress = "0.0.0.0"

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
}

// Server is a TURN server.
type Server struct {
	Options
	context.Context
	cancel context.CancelFunc
	log    *slog.Logger
}

// NewServer creates and starts a new TURN server.
func NewServer(ctx context.Context, o Options) *Server {
	log := context.LoggerFrom(ctx).With("component", "turn-server")
	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{Options: o, Context: ctx, cancel: cancel, log: log}
	return server
}

// ListenAndServe starts the TURN server and blocks until the server exits.
func (s *Server) ListenAndServe() error {
	if s.PortRange == "" {
		s.PortRange = DefaultPortRange
	}
	if s.RelayAddressUDP == "" {
		s.RelayAddressUDP = DefaultRelayAddress
	}
	startPort, endPort, err := netutil.ParsePortRange(s.PortRange)
	if err != nil {
		return fmt.Errorf("failed to parse port range: %w", err)
	}
	if s.ListenUDP == "" {
		s.ListenUDP = DefaultListenAddress
	}
	udpConn, err := net.ListenPacket("udp", s.ListenUDP)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}
	defer udpConn.Close()
	log := s.log
	log.Info("Listening for STUN requests", slog.String("listen-addr", s.ListenUDP))
	pktConn := &stunLogger{
		PacketConn: udpConn,
		log:        log.With("channel", "stun"),
	}
	// Create the turn server
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm:         s.Realm,
		LoggerFactory: logging.NewSTUNLoggerFactory(log.With("server", "turn")),
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
					RelayAddress: net.ParseIP(s.PublicIP),
					Address:      s.RelayAddressUDP,
					MinPort:      uint16(startPort),
					MaxPort:      uint16(endPort),
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create TURN server: %w", err)
	}
	defer srv.Close()
	// Block until the server exits
	<-s.Done()
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	context.LoggerFrom(ctx).Info("Shutting down TURN server")
	s.cancel()
	return nil
}
