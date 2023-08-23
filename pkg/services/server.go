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
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/meshdb/rbac"
	"github.com/webmeshproj/webmesh/pkg/services/admin"
	"github.com/webmeshproj/webmesh/pkg/services/dashboard"
	"github.com/webmeshproj/webmesh/pkg/services/membership"
	"github.com/webmeshproj/webmesh/pkg/services/meshapi"
	"github.com/webmeshproj/webmesh/pkg/services/meshdns"
	"github.com/webmeshproj/webmesh/pkg/services/node"
	"github.com/webmeshproj/webmesh/pkg/services/turn"
	"github.com/webmeshproj/webmesh/pkg/services/webrtc"
)

// Server is the gRPC server.
type Server struct {
	opts      *Options
	store     mesh.Mesh
	srv       *grpc.Server
	turn      *turn.Server
	meshdns   *meshdns.Server
	dashboard *dashboard.Server
	log       *slog.Logger
	mu        sync.Mutex
}

// NewServer returns a new Server.
func NewServer(store mesh.Mesh, o *Options) (*Server, error) {
	log := slog.Default().With("component", "server")
	if err := o.Validate(); err != nil {
		return nil, err
	}
	serveOpts, err := o.ServerOptions(store, log)
	if err != nil {
		return nil, err
	}
	server := &Server{
		srv:   grpc.NewServer(serveOpts...),
		opts:  o,
		store: store,
		log:   log,
	}
	var rbacDisabled bool
	maxTries := 5
	for i := 0; i < maxTries; i++ {
		rbacDisabled, err = rbac.New(store.Storage()).IsDisabled(context.Background())
		if err != nil {
			log.Error("failed to check rbac status", "error", err.Error())
			if i == maxTries-1 {
				return nil, err
			}
			time.Sleep(1 * time.Second)
			continue
		}
		break
	}
	insecureServices := !store.Plugins().HasAuth() || rbacDisabled
	if insecureServices {
		log.Warn("running services without authorization")
	}
	if o.API != nil {
		if o.API.Admin {
			log.Debug("registering admin api")
			v1.RegisterAdminServer(server, admin.New(store, insecureServices))
		}
		if o.API.Mesh {
			log.Debug("registering mesh api")
			v1.RegisterMeshServer(server, meshapi.NewServer(store))
		}
		if o.API.WebRTC {
			log.Debug("registering webrtc api")
			stunURLs := strings.Split(o.API.STUNServers, ",")
			v1.RegisterWebRTCServer(server, webrtc.NewServer(store, stunURLs, insecureServices))
		}
	}
	if o.MeshDNS != nil && o.MeshDNS.Enabled {
		log.Debug("registering mesh dns")
		server.meshdns = meshdns.NewServer(&meshdns.Options{
			UDPListenAddr:     o.MeshDNS.ListenUDP,
			TCPListenAddr:     o.MeshDNS.ListenTCP,
			ReusePort:         o.MeshDNS.ReusePort,
			Compression:       o.MeshDNS.EnableCompression,
			RequestTimeout:    o.MeshDNS.RequestTimeout,
			Forwarders:        o.MeshDNS.Forwarders,
			DisableForwarding: o.MeshDNS.DisableForwarding,
			CacheSize:         o.MeshDNS.CacheSize,
		})
		err := server.meshdns.RegisterDomain(meshdns.DomainOptions{
			Mesh:                store,
			SubscribeForwarders: o.MeshDNS.SubscribeForwarders,
		})
		if err != nil {
			return nil, fmt.Errorf("register meshdns domain: %w", err)
		}
	}
	if o.Dashboard != nil && o.Dashboard.Enabled {
		log.Debug("registering dashboard handlers")
		server.dashboard, err = dashboard.NewServer(server.srv, o.Dashboard)
		if err != nil {
			return nil, err
		}
	}
	// Register the membership API if we are a raft member
	isRaftMember := store.Raft().IsVoter() || store.Raft().IsObserver()
	if isRaftMember {
		log.Debug("registering membership service")
		v1.RegisterMembershipServer(server, membership.NewServer(store, insecureServices))
	}
	// Always register the node server
	log.Debug("registering node service")
	v1.RegisterNodeServer(server, node.NewServer(store, o.ToFeatureSet(isRaftMember), insecureServices))
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
	s.mu.Lock()
	if s.opts.Metrics != nil && s.opts.Metrics.Enabled {
		go func() {
			s.log.Info(fmt.Sprintf("Starting HTTP metrics server on %s", s.opts.Metrics.ListenAddress))
			http.Handle(s.opts.Metrics.Path, promhttp.Handler())
			if err := http.ListenAndServe(s.opts.Metrics.ListenAddress, nil); err != nil {
				s.log.Error("metrics server failed", slog.String("error", err.Error()))
			}
		}()
	}
	if s.opts.TURN != nil && s.opts.TURN.Enabled {
		var err error
		s.log.Info(fmt.Sprintf("Starting TURN server on %s:%d", s.opts.TURN.ListenAddress, s.opts.TURN.ListenPort))
		s.turn, err = turn.NewServer(&turn.Options{
			PublicIP:        s.opts.TURN.PublicIP,
			RelayAddressUDP: s.opts.TURN.ListenAddress,
			ListenUDP:       fmt.Sprintf(":%d", s.opts.TURN.ListenPort),
			Realm:           s.opts.TURN.ServerRealm,
			PortRange:       s.opts.TURN.STUNPortRange,
		})
		if err != nil {
			s.mu.Unlock()
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
		s.mu.Unlock()
		return fmt.Errorf("start TCP listener: %w", err)
	}
	defer lis.Close()
	s.mu.Unlock()
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

// Stop stops the gRPC server gracefully. You cannot use the server again
// after calling Stop.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.turn != nil {
		s.log.Info("Shutting down TURN server")
		if err := s.turn.Close(); err != nil {
			s.log.Error("turn server shutdown failed", slog.String("error", err.Error()))
		}
		s.turn = nil
	}
	if s.meshdns != nil {
		s.log.Info("Shutting down meshdns server")
		if err := s.meshdns.Shutdown(); err != nil {
			s.log.Error("meshdns server shutdown failed", slog.String("error", err.Error()))
		}
		s.meshdns = nil
	}
	if s.dashboard != nil {
		s.log.Info("Shutting down dashboard server")
		if err := s.dashboard.Shutdown(context.Background()); err != nil {
			s.log.Error("dashboard server shutdown failed", slog.String("error", err.Error()))
		}
		s.dashboard = nil
	}
	if s.srv != nil {
		s.log.Info("Shutting down gRPC server")
		s.srv.GracefulStop()
		s.srv = nil
	}
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
	_, err := s.store.Leader()
	if err != nil {
		s.log.Error("failed to get leader", "error", err)
		return healthpb.HealthCheckResponse_NOT_SERVING
	}
	return healthpb.HealthCheckResponse_SERVING
}
