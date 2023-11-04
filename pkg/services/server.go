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
	"reflect"
	"strings"
	"sync"

	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport/libp2p"
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

// MeshServers is a list of MeshServers.
type MeshServers []MeshServer

// GetByType iterates the list of given servers and returns
// one of the given type.
func (s MeshServers) GetByType(t any) (MeshServer, bool) {
	for _, srv := range s {
		if reflect.TypeOf(srv) == reflect.TypeOf(t) {
			return srv, true
		}
	}
	return nil, false
}

// GetByType is a generic function that can be used to search for the
// given server and automatically convert it to the given type.
func GetByType[T any](srvs MeshServers, t T) (T, bool) {
	srv, ok := srvs.GetByType(t)
	if !ok {
		var out T
		return out, false
	}
	return srv.(T), true
}

// Options contains the configuration for the gRPC server.
type Options struct {
	// DisableGRPC disables the gRPC server and only runs the MeshServers.
	DisableGRPC bool
	// WebEnabled is true if the grpc-web server should be enabled.
	WebEnabled bool
	// EnableCORS is true if CORS should be enabled with grpc-web.
	EnableCORS bool
	// AllowedOrigins is a list of allowed origins for CORS.
	AllowedOrigins []string
	// ListenAddress is the address to start the gRPC server on.
	ListenAddress string
	// ServerOptions are options for the server. This should include
	// any registered authentication mechanisms.
	ServerOptions []grpc.ServerOption
	// LibP2POptions are options for serving the gRPC server over libp2p.
	LibP2POptions *LibP2POptions
	// Servers are additional servers to manage alongside the gRPC server.
	Servers MeshServers
}

// LibP2POptions are options for serving the gRPC server over libp2p.
type LibP2POptions struct {
	// HostOptions are options for the libp2p host.
	HostOptions libp2p.HostOptions
	// Announce will announce the host on the DHT at the given rendezvous if true.
	Announce bool
	// Rendezvous is the rendezvous string to use for libp2p.
	Rendezvous string
}

// GetServer returns the server of the given type.
func (o *Options) GetServer(typ any) (MeshServer, bool) {
	return o.Servers.GetByType(typ)
}

// Server is the gRPC server.
type Server struct {
	opts    Options
	hostlis net.Listener
	lis     *net.TCPListener
	srv     *grpc.Server
	websrv  *http.Server
	srvs    []MeshServer
	log     *slog.Logger
	mu      sync.Mutex
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
	if !o.DisableGRPC {
		server.srv = grpc.NewServer(o.ServerOptions...)
		log.Debug("Registering reflection service")
		reflection.Register(server)
		// Go ahead and start the listener.
		if o.ListenAddress != "" {
			log.Debug("Starting TCP listener", "address", o.ListenAddress)
			lis, err := net.Listen("tcp", o.ListenAddress)
			if err != nil {
				return nil, fmt.Errorf("start TCP listener: %w", err)
			}
			server.lis = lis.(*net.TCPListener)
		}
		if o.LibP2POptions != nil {
			log.Debug("Starting libp2p host listener")
			hostOpts := o.LibP2POptions.HostOptions
			host, err := libp2p.NewHost(ctx, hostOpts)
			if err != nil {
				return nil, fmt.Errorf("start libp2p host: %w", err)
			}
			if o.LibP2POptions.Announce {
				log.Debug("Announcing libp2p host to the DHT")
				discovery, err := libp2p.WrapHostWithDiscovery(ctx, host, hostOpts.BootstrapPeers, hostOpts.ConnectTimeout)
				if err != nil {
					return nil, fmt.Errorf("wrap host with discovery: %w", err)
				}
				discovery.Announce(ctx, o.LibP2POptions.Rendezvous, 0)
			}
			server.hostlis = host.RPCListener()
		}
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
				s.log.Error("Mesh server failed", slog.String("error", err.Error()))
				return err
			}
			return nil
		})
	}
	if s.lis != nil {
		g.Go(func() error {
			defer s.lis.Close()
			if s.opts.WebEnabled {
				s.log.Info(fmt.Sprintf("Starting gRPC-web server on %s", s.lis.Addr().String()))
				wrapped := grpcweb.WrapServer(s.srv, grpcweb.WithWebsockets(true))
				handler := http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
					if s.opts.EnableCORS {
						s.log.Debug("Handling CORS options for request", "origin", req.Header.Get("Origin"))
						resp.Header().Set("Access-Control-Allow-Origin", strings.Join(s.opts.AllowedOrigins, ", "))
						resp.Header().Set("Access-Control-Allow-Credentials", "true")
						resp.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Grpc-Web, X-User-Agent")
						resp.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
						if req.Method == http.MethodOptions {
							resp.WriteHeader(http.StatusOK)
							return
						}
					}
					if wrapped.IsGrpcWebRequest(req) {
						s.log.Debug("Handling gRPC-Web request")
						wrapped.ServeHTTP(resp, req)
						return
					}
					// Fall down to the gRPC server
					s.log.Debug("Handling gRPC request")
					s.srv.ServeHTTP(resp, req)
				})
				s.websrv = &http.Server{
					Handler: h2c.NewHandler(handler, &http2.Server{}),
				}
				if err := s.websrv.Serve(s.lis); err != nil && err != http.ErrServerClosed {
					return fmt.Errorf("grpc-web serve: %w", err)
				}
				return nil
			}
			s.log.Info(fmt.Sprintf("Starting gRPC server on %s", s.lis.Addr().String()))
			if err := s.srv.Serve(s.lis); err != nil {
				return fmt.Errorf("grpc serve: %w", err)
			}
			return nil
		})
	}
	if s.hostlis != nil {
		g.Go(func() error {
			defer s.hostlis.Close()
			s.log.Info(fmt.Sprintf("Starting libp2p gRPC server on %s", s.hostlis.Addr().String()))
			if err := s.srv.Serve(s.hostlis); err != nil {
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

// GRPCListenPort returns the port the gRPC server is listening on.
func (s *Server) GRPCListenPort() int {
	if s.lis == nil {
		return 0
	}
	return s.lis.Addr().(*net.TCPAddr).Port
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
			s.log.Error("Mesh server shutdown failed", slog.String("error", err.Error()))
		}
	}
	if s.websrv != nil {
		s.log.Info("Shutting down gRPC-web server")
		if err := s.websrv.Shutdown(ctx); err != nil {
			s.log.Error("gRPC-web server shutdown failed", slog.String("error", err.Error()))
		}
	} else if s.srv != nil {
		s.log.Info("Shutting down gRPC server")
		s.srv.GracefulStop()
	}
}
