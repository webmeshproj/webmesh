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
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/pion/turn/v2"
	"golang.org/x/net/websocket"

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
	// ListenTCP is the address the TURN server listens on for TCP requests.
	ListenTCP string
	// Realm is the realm used for authentication.
	Realm string
	// PortRange is the range of ports the TURN server will use for relaying.
	PortRange string
	// EnableCampfire enables relaying campfire packets.
	EnableCampfire bool
	// EnableCampfireWebsockets enables relaying campfire packets over websockets.
	// If ListenTCP is not set, ListenUDP will be used.
	EnableCampfireWebsockets bool
	// TLSCertFile is the path to the TLS certificate file when serving the TURN server over TLS.
	TLSCertFile string
	// TLSKeyFile is the path to the TLS key file when serving the TURN server over TLS.
	TLSKeyFile string
}

// Server is a TURN server.
type Server struct {
	*turn.Server
	conn net.PacketConn
	http *http.Server
}

// NewServer creates and starts a new TURN server.
func NewServer(o *Options) (*Server, error) {
	if o.PortRange == "" {
		o.PortRange = "49152-65535"
	}
	if o.RelayAddressUDP == "" {
		o.RelayAddressUDP = "0.0.0.0"
	}
	startPort, endPort, err := util.ParsePortRange(o.PortRange)
	if err != nil {
		return nil, fmt.Errorf("failed to parse port range: %w", err)
	}
	if o.ListenUDP == "" {
		return nil, fmt.Errorf("listen port UDP must be set")
	}
	if o.EnableCampfireWebsockets && !o.EnableCampfire {
		return nil, fmt.Errorf("campfire websockets cannot be enabled without campfire")
	}
	if o.EnableCampfireWebsockets && o.ListenTCP == "" {
		o.ListenTCP = o.ListenUDP
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
	var cfManager *campfireManager
	if o.EnableCampfire {
		log.Info("Enabling campfire protocol extensions")
		cfManager = NewCampfireManager(pktConn, log.With("channel", "campfire"))
		pktConn = cfManager
	}
	// Create the turn server
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
	server := &Server{Server: s, conn: pktConn}
	if o.EnableCampfireWebsockets {
		// Create the websocket server
		var tlsConfig *tls.Config
		if o.TLSCertFile != "" && o.TLSKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(o.TLSCertFile, o.TLSKeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load TLS key pair: %w", err)
			}
			tlsConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
			}
		}
		ln, err := net.Listen("tcp", o.ListenTCP)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on TCP: %w", err)
		}
		wssrv := &websocket.Server{
			Handler: websocket.Handler(cfManager.handleWebsocket),
		}
		server.http = &http.Server{
			TLSConfig: tlsConfig,
			Handler:   handleCORSPreflight(wssrv.ServeHTTP),
		}
		go func() {
			defer ln.Close()
			var err error
			if tlsConfig != nil {
				log.Info("Listening for campfire websocket requests over TLS", slog.String("listen-addr", o.ListenTCP))
				err = server.http.ServeTLS(ln, "", "")
			} else {
				log.Info("Listening for campfire websocket requests", slog.String("listen-addr", o.ListenTCP))
				err = server.http.Serve(ln)
			}
			if err != nil && err != http.ErrServerClosed {
				log.Error("Failed to serve campfire websockets", slog.String("error", err.Error()))
			}
		}()
	}
	return server, nil
}

// ListenPort returns the UDP port the TURN server is listening on.
func (s *Server) ListenPort() int {
	return s.conn.LocalAddr().(*net.UDPAddr).Port
}

func (s *Server) Close() error {
	if s.http != nil {
		if err := s.http.Close(); err != nil {
			slog.Default().Error("failed to close campfire websocket server", slog.String("error", err.Error()))
		}
	}
	return s.Server.Close()
}

func handleCORSPreflight(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			// TODO: Allow user to restrict to specific origins
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}
