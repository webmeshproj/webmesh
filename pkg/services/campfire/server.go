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

// Package campfire provides the campfire service to webmesh clients.
package campfire

import (
	"errors"
	"flag"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb"
	"github.com/webmeshproj/webmesh/pkg/util"
)

// DefaultListenUDP is the default UDP address to listen on.
const DefaultListenUDP = ":4095"

const (
	CampfireEnabledEnvVar   = "SERVICES_CAMPFIRE_ENABLED"
	CampfireListenUDPEnvVar = "SERVICES_CAMPFIRE_LISTEN_UDP"
)

// Options are options for the campfire service.
type Options struct {
	// Enabled is whether the campfire service is enabled.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty" toml:"enabled,omitempty"`
	// ListenUDP is the UDP address to listen on.
	ListenUDP string `json:"listen-udp,omitempty" yaml:"listen-udp,omitempty" toml:"listen-udp,omitempty"`
}

// NewOptions returns new campfire service options.
func NewOptions() *Options {
	return &Options{
		Enabled:   false,
		ListenUDP: DefaultListenUDP,
	}
}

// BindFlags binds the campfire service options to flags.
func (o *Options) BindFlags(fs *flag.FlagSet, prefix ...string) {
	var p string
	if len(prefix) > 0 {
		p = strings.Join(prefix, ".") + "."
	}
	fs.BoolVar(&o.Enabled, p+"services.campfire.enabled", util.GetEnvDefault(CampfireEnabledEnvVar, "false") == "true", "whether the campfire service is enabled")
	fs.StringVar(&o.ListenUDP, p+"services.campfire.listen-udp", util.GetEnvDefault(CampfireListenUDPEnvVar, DefaultListenUDP), "the UDP address to listen on")
}

// Validate validates the campfire service options.
func (o *Options) Validate() error {
	if o == nil {
		return nil
	}
	if o.Enabled {
		if o.ListenUDP == "" {
			return errors.New("campfire listen UDP address is required")
		}
		_, _, err := net.SplitHostPort(o.ListenUDP)
		if err != nil {
			return errors.New("campfire listen UDP address is invalid")
		}
	}
	return nil
}

// Server is the campfire service.
type Server struct {
	opts   Options
	mesh   meshdb.Store
	rooms  *RoomManager
	closec chan struct{}
	log    *slog.Logger
}

// NewServer returns a new campfire service.
func NewServer(mesh meshdb.Store, opts *Options) *Server {
	return &Server{
		opts:   *opts,
		mesh:   mesh,
		closec: make(chan struct{}),
		log:    slog.Default().With("service", "campfire"),
	}
}

// ListenAndServe listens and serves the campfire service.
func (s *Server) ListenAndServe(ctx context.Context) error {
	log := s.log
	log.Info("starting campfire udp service", "addr", s.opts.ListenUDP)
	pkt, err := net.ListenPacket("udp", s.opts.ListenUDP)
	if err != nil {
		return err
	}
	defer pkt.Close()
	s.rooms, err = NewRoomManager(s.mesh, pkt)
	if err != nil {
		return err
	}
	go s.handlePktRead(pkt)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.closec:
	}
	return nil
}

// Shutdown shuts down the campfire service.
func (s *Server) Shutdown(ctx context.Context) {
	s.rooms.Close()
	close(s.closec)
}

func (s *Server) handlePktRead(c net.PacketConn) {
	log := s.log
	for {
		select {
		case <-s.closec:
			return
		default:
		}
		if err := c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			log.Error("set read deadline on udp packet conn", "error", err)
			continue
		}
		buf := make([]byte, 1024)
		n, addr, err := c.ReadFrom(buf)
		if err != nil {
			if err == net.ErrClosed {
				return
			}
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				continue
			}
			log.Error("read from udp packet conn", "error", err)
			continue
		}
		msg := buf[:n]
		m, err := ParseMessage(msg)
		if err != nil {
			log.Error("parse message", "error", err)
			continue
		}
		go s.rooms.HandleMessage(addr, &m)
	}
}
