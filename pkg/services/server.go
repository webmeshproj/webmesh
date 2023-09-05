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
	"sync"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// DefaultGRPCPort is the default port for the gRPC server.
const DefaultGRPCPort = 8443

// DefaultGRPCListenAddress is the default listen address for the gRPC server.
const DefaultGRPCListenAddress = "[::]:8443"

// MeshServer is the generic interface for additional services that
// can be managed by this server.
type MeshServer interface {
	// ListenAndServe starts the server and blocks until the server exits.
	ListenAndServe() error
	// Shutdown attempts to stops the server gracefully.
	Shutdown(ctx context.Context) error
}

// Options contains the configuration for the gRPC server.
type Options struct {
	// DisableGRPC disables the gRPC server and only runs the MeshServers.
	DisableGRPC bool
	// ListenAddress is the address to start the gRPC server on.
	ListenAddress string
	// ServerOptions are options for the server. This should include
	// any registered authentication mechanisms.
	ServerOptions []grpc.ServerOption
	// Servers are additional servers to manage alongside the gRPC server.
	Servers []MeshServer
}

// Server is the gRPC server.
type Server struct {
	opts Options
	srv  *grpc.Server
	srvs []MeshServer
	log  *slog.Logger
	mu   sync.Mutex
}

// NewServer returns a new Server.
// TODO: We need to dynamically expose certain services only to the internal mesh.
func NewServer(ctx context.Context, o Options) (*Server, error) {
	log := context.LoggerFrom(ctx).With("component", "mesh-services")
	server := &Server{
		opts: o,
		srvs: o.Servers,
		log:  log,
	}
	// Register the reflection service
	if !o.DisableGRPC {
		server.srv = grpc.NewServer(o.ServerOptions...)
		log.Debug("Registering reflection service")
		reflection.Register(server)
	}
	return server, nil
}

// ListenAndServe starts the gRPC server and optional metrics server
// then blocks until the gRPC server exits.
func (s *Server) ListenAndServe() error {
	s.mu.Lock()
	var g errgroup.Group
	for _, srv := range s.srvs {
		sr := srv
		g.Go(func() error {
			if err := sr.ListenAndServe(); err != nil {
				s.log.Error("mesh server failed", slog.String("error", err.Error()))
				return err
			}
			return nil
		})
	}
	if !s.opts.DisableGRPC {
		g.Go(func() error {
			s.log.Info(fmt.Sprintf("Starting gRPC server on %s", s.opts.ListenAddress))
			lis, err := net.Listen("tcp", s.opts.ListenAddress)
			if err != nil {
				s.mu.Unlock()
				return fmt.Errorf("start TCP listener: %w", err)
			}
			defer lis.Close()
			if err := s.srv.Serve(lis); err != nil {
				return fmt.Errorf("grpc serve: %w", err)
			}
			return nil
		})
	}
	s.mu.Unlock()
	return g.Wait()
}

// RegisterService implements grpc.RegistrarService.
func (s *Server) RegisterService(desc *grpc.ServiceDesc, impl any) {
	if s.opts.DisableGRPC {
		return
	}
	s.srv.RegisterService(desc, impl)
}

// GetServiceInfo implements reflection.ServiceInfoProvider.
func (s *Server) GetServiceInfo() map[string]grpc.ServiceInfo {
	if s.opts.DisableGRPC {
		return map[string]grpc.ServiceInfo{}
	}
	return s.srv.GetServiceInfo()
}

// Shutdown stops the gRPC server and all mesh services gracefully.
// You cannot use the server again after calling Stop.
func (s *Server) Shutdown(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, srv := range s.srvs {
		s.log.Debug("Shutting down mesh server")
		err := srv.Shutdown(ctx)
		if err != nil {
			s.log.Error("mesh server shutdown failed", slog.String("error", err.Error()))
		}
	}
	if s.srv != nil {
		s.log.Info("Shutting down gRPC server")
		s.srv.GracefulStop()
	}
}
