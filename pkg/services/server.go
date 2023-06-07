/*
Copyright 2023.

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
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/webmeshproj/node/pkg/services/admin"
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
	opts    *Options
	srv     *grpc.Server
	turn    *turn.Server
	meshdns *meshdns.Server
	log     *slog.Logger
}

// NewServer returns a new Server.
func NewServer(store store.Store, o *Options) (*Server, error) {
	log := slog.Default().With("component", "server")
	opts, tlsConfig, err := o.ServerOptions(store)
	if err != nil {
		return nil, err
	}
	server := &Server{
		srv:  grpc.NewServer(opts...),
		opts: o,
		log:  log,
	}
	if o.EnableAdminAPI {
		log.Debug("registering admin api")
		v1.RegisterAdminServer(server, admin.New(store))
	}
	if o.EnableMeshAPI {
		log.Debug("registering mesh api")
		v1.RegisterMeshServer(server, meshapi.NewServer(store))
	}
	if o.EnablePeerDiscoveryAPI {
		log.Debug("registering peer discovery api")
		v1.RegisterPeerDiscoveryServer(server, peerdiscovery.NewServer(store))
	}
	if o.EnableWebRTCAPI {
		var stunURLs []string
		if (o.EnableTURNServer && !o.ExclusiveTURNServer) && o.STUNServers != "" {
			stunURLs = strings.Split(o.STUNServers, ",")
		}
		if o.EnableTURNServer {
			if o.TURNServerEndpoint != "" {
				stunURLs = append(stunURLs, o.TURNServerEndpoint)
			} else {
				stunURLs = append(stunURLs, fmt.Sprintf("stun:%s:%d", o.TURNServerPublicIP, o.TURNServerPort))
			}
		}
		v1.RegisterWebRTCServer(server, webrtc.NewServer(store, tlsConfig, stunURLs))
	}
	if o.EnableMeshDNS {
		log.Debug("registering mesh dns")
		server.meshdns = meshdns.NewServer(store, &meshdns.Options{
			UDPListenAddr:  o.MeshDNSListenUDP,
			TCPListenAddr:  o.MeshDNSListenTCP,
			TSIGKey:        o.MeshDNSTSIGKey,
			ReusePort:      o.MeshDNSReusePort,
			Compression:    o.MeshDNSCompression,
			Domain:         o.MeshDNSDomain,
			RequestTimeout: o.MeshDNSRequestTimeout,
		})
	}
	log.Debug("registering node server")
	// Always register the node server
	v1.RegisterNodeServer(server, node.NewServer(store, tlsConfig, o.ToFeatureSet()))
	return server, nil
}

// ListenAndServe starts the gRPC server and optional metrics server
// then blocks until the gRPC server exits.
func (s *Server) ListenAndServe() error {
	reflection.Register(s.srv)
	if s.opts.EnableMetrics {
		go func() {
			s.log.Info(fmt.Sprintf("Starting HTTP metrics server on %s", s.opts.MetricsListenAddress))
			http.Handle(s.opts.MetricsPath, promhttp.Handler())
			if err := http.ListenAndServe(s.opts.MetricsListenAddress, nil); err != nil {
				s.log.Error("metrics server failed", slog.String("error", err.Error()))
			}
		}()
	}
	if s.opts.EnableTURNServer {
		var err error
		s.log.Info(fmt.Sprintf("Starting TURN server on %s:%d", s.opts.TURNServerListenAddress, s.opts.TURNServerPort))
		s.turn, err = turn.NewServer(&turn.Options{
			PublicIP:         s.opts.TURNServerPublicIP,
			ListenAddressUDP: s.opts.TURNServerListenAddress,
			ListenPortUDP:    s.opts.TURNServerPort,
			Realm:            s.opts.TURNServerRealm,
			PortRange:        s.opts.STUNPortRange,
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
	s.log.Info(fmt.Sprintf("Starting gRPC server on %s", s.opts.GRPCListenAddress))
	lis, err := net.Listen("tcp", s.opts.GRPCListenAddress)
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
	s.log.Info("Shutting down gRPC server")
	s.srv.GracefulStop()
}

// InterceptorLogger returns a logging.Logger that logs to the given slog.Logger.
func InterceptorLogger(l *slog.Logger) logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		l.Log(ctx, slog.Level(lvl), msg, fields...)
	})
}
