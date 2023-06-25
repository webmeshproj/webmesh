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

// Package services contains the gRPC server for inter-node communication.
package services

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/services/admin"
	"github.com/webmeshproj/node/pkg/services/dashboard"
	"github.com/webmeshproj/node/pkg/services/meshapi"
	"github.com/webmeshproj/node/pkg/services/meshdns"
	"github.com/webmeshproj/node/pkg/services/node"
	"github.com/webmeshproj/node/pkg/services/peerdiscovery"
	"github.com/webmeshproj/node/pkg/services/turn"
	"github.com/webmeshproj/node/pkg/services/webrtc"
	"github.com/webmeshproj/node/pkg/store"
)

// Server is the gRPC server.
type Server struct {
	opts      *Options
	srv       *grpc.Server
	turn      *turn.Server
	meshdns   *meshdns.Server
	dashboard *dashboard.Server
	store     store.Store
	log       *slog.Logger
}

// NewServer returns a new Server.
func NewServer(store store.Store, o *Options) (*Server, error) {
	log := slog.Default().With("component", "server")
	if err := o.Validate(); err != nil {
		return nil, err
	}
	serveOpts, proxyCreds, err := o.ServerOptions(store, log)
	if err != nil {
		return nil, err
	}
	server := &Server{
		srv:   grpc.NewServer(serveOpts...),
		opts:  o,
		store: store,
		log:   log,
	}
	insecureServices := !store.Plugins().HasAuth()
	if insecureServices {
		log.Warn("running services without authentication")
	}
	if o.API.Admin {
		log.Debug("registering admin api")
		v1.RegisterAdminServer(server, admin.New(store, insecureServices))
	}
	if o.API.Mesh {
		log.Debug("registering mesh api")
		v1.RegisterMeshServer(server, meshapi.NewServer(store))
	}
	if o.API.PeerDiscovery {
		log.Debug("registering peer discovery api")
		v1.RegisterPeerDiscoveryServer(server, peerdiscovery.NewServer(store))
	}
	if o.API.WebRTC {
		log.Debug("registering webrtc api")
		stunURLs := strings.Split(o.API.STUNServers, ",")
		v1.RegisterWebRTCServer(server, webrtc.NewServer(store, proxyCreds, stunURLs, insecureServices))
	}
	if o.MeshDNS.Enabled {
		log.Debug("registering mesh dns")
		server.meshdns = meshdns.NewServer(store, &meshdns.Options{
			UDPListenAddr:  o.MeshDNS.ListenUDP,
			TCPListenAddr:  o.MeshDNS.ListenTCP,
			TSIGKey:        o.MeshDNS.TSIGKey,
			ReusePort:      o.MeshDNS.ReusePort,
			Compression:    o.MeshDNS.EnableCompression,
			Domain:         o.MeshDNS.Domain,
			RequestTimeout: o.MeshDNS.RequestTimeout,
		})
	}
	if o.Dashboard.Enabled {
		log.Debug("registering dashboard handlers")
		server.dashboard, err = dashboard.NewServer(server.srv, o.Dashboard)
		if err != nil {
			return nil, err
		}
	}
	// Always register the node server
	log.Debug("registering node server")
	v1.RegisterNodeServer(server, node.NewServer(store, proxyCreds, o.ToFeatureSet(), insecureServices))
	// Register the health service
	log.Debug("registering health service")
	healthpb.RegisterHealthServer(server, server)
	// Register the reflection service
	log.Debug("registering reflection service")
	reflection.Register(server)
	return server, nil
}

// ListenAndServe starts the gRPC server and optional metrics server
// then blocks until the gRPC server exits.
func (s *Server) ListenAndServe() error {
	if s.opts.Metrics.Enabled {
		go func() {
			s.log.Info(fmt.Sprintf("Starting HTTP metrics server on %s", s.opts.Metrics.ListenAddress))
			http.Handle(s.opts.Metrics.Path, promhttp.Handler())
			if err := http.ListenAndServe(s.opts.Metrics.ListenAddress, nil); err != nil {
				s.log.Error("metrics server failed", slog.String("error", err.Error()))
			}
		}()
	}
	if s.opts.TURN.Enabled {
		var err error
		s.log.Info(fmt.Sprintf("Starting TURN server on %s:%d", s.opts.TURN.ListenAddress, s.opts.TURN.ListenPort))
		s.turn, err = turn.NewServer(&turn.Options{
			PublicIP:         s.opts.TURN.PublicIP,
			ListenAddressUDP: s.opts.TURN.ListenAddress,
			ListenPortUDP:    s.opts.TURN.ListenPort,
			Realm:            s.opts.TURN.ServerRealm,
			PortRange:        s.opts.TURN.STUNPortRange,
		})
		if err != nil {
			return fmt.Errorf("create turn server: %w", err)
		}
	}
	if s.meshdns != nil {
		go func() {
			if err := s.meshdns.ListenAndServe(); err != nil {
				s.log.Error("meshdns server failed", slog.String("error", err.Error()))
			}
		}()
	}
	if s.dashboard != nil {
		go func() {
			if err := s.dashboard.ListenAndServe(); err != nil {
				s.log.Error("dashboard server failed", slog.String("error", err.Error()))
			}
		}()
	}
	s.log.Info(fmt.Sprintf("Starting gRPC server on %s", s.opts.ListenAddress))
	lis, err := net.Listen("tcp", s.opts.ListenAddress)
	if err != nil {
		return fmt.Errorf("start TCP listener: %w", err)
	}
	defer lis.Close()
	if err := s.srv.Serve(lis); err != nil {
		return fmt.Errorf("grpc serve: %w", err)
	}
	return nil
}

// RegisterService implements grpc.RegistrarService.
func (s *Server) RegisterService(desc *grpc.ServiceDesc, impl any) {
	s.srv.RegisterService(desc, impl)
}

// GetServiceInfo implements reflection.ServiceInfoProvider.
func (s *Server) GetServiceInfo() map[string]grpc.ServiceInfo {
	return s.srv.GetServiceInfo()
}

// Stop stops the gRPC server gracefully.
func (s *Server) Stop() {
	if s.turn != nil {
		s.log.Info("Shutting down TURN server")
		if err := s.turn.Close(); err != nil {
			s.log.Error("turn server shutdown failed", slog.String("error", err.Error()))
		}
	}
	if s.meshdns != nil {
		s.log.Info("Shutting down meshdns server")
		if err := s.meshdns.Shutdown(); err != nil {
			s.log.Error("meshdns server shutdown failed", slog.String("error", err.Error()))
		}
	}
	if s.dashboard != nil {
		s.log.Info("Shutting down dashboard server")
		if err := s.dashboard.Shutdown(context.Background()); err != nil {
			s.log.Error("dashboard server shutdown failed", slog.String("error", err.Error()))
		}
	}
	s.log.Info("Shutting down gRPC server")
	s.srv.GracefulStop()
}

// Check implements grpc.health.v1.HealthServer.
func (s *Server) Check(context.Context, *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	return &healthpb.HealthCheckResponse{
		Status: s.currentStatus(),
	}, nil
}

// Watch implements grpc.health.v1.HealthServer.
func (s *Server) Watch(_ *healthpb.HealthCheckRequest, srv healthpb.Health_WatchServer) error {
	last := s.currentStatus()
	err := srv.Send(&healthpb.HealthCheckResponse{
		Status: last,
	})
	if err != nil {
		return err
	}
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-srv.Context().Done():
			return nil
		case <-t.C:
			current := s.currentStatus()
			if last != current {
				last = current
				err := srv.Send(&healthpb.HealthCheckResponse{
					Status: current,
				})
				if err != nil {
					return err
				}
			}
		}
	}
}

func (s *Server) currentStatus() healthpb.HealthCheckResponse_ServingStatus {
	if s.store.Ready() {
		return healthpb.HealthCheckResponse_SERVING
	}
	return healthpb.HealthCheckResponse_NOT_SERVING
}
