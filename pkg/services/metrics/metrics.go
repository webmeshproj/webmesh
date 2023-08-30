//go:build !wasm

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

// Package metrics contains the HTTP server for exposing Prometheus metrics.
package metrics

import (
	"log/slog"
	"net/http"

	"github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	promapi "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// DefaultListenAddress is the default listen address for the node Metrics.
const DefaultListenAddress = "[::]:8080"

// DefaultPath is the default path for the node Metrics.
const DefaultPath = "/metrics"

// Options contains the configuration for exposing node metrics.
type Options struct {
	// ListenAddress is the address to start the metrics server on.
	ListenAddress string
	// Path is the path to expose metrics on.
	Path string
}

// Server is the metrics server.
type Server struct {
	Options
	srv *http.Server
	log *slog.Logger
}

// New returns a new metrics server.
func New(ctx context.Context, o Options) *Server {
	return &Server{
		Options: o,
		log:     context.LoggerFrom(ctx),
	}
}

// ListenAndServe starts the server and blocks until the server exits.
func (s *Server) ListenAndServe() error {
	s.log.Info("Starting Prometheus metrics server", slog.String("listen_address", s.ListenAddress), slog.String("path", s.Path))
	srv := &http.Server{
		Addr: s.ListenAddress,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == s.Path {
				promhttp.Handler().ServeHTTP(w, r)
			} else {
				http.NotFound(w, r)
			}
		}),
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		s.log.Error("metrics server failed", slog.String("error", err.Error()))
	}
	return nil
}

// Shutdown attempts to stop the server gracefully.
func (s *Server) Shutdown(ctx context.Context) error {
	context.LoggerFrom(ctx).Info("Shutting down Prometheus metrics server")
	return s.srv.Shutdown(ctx)
}

// AppendMetricsMiddlewares appends the Prometheus metrics middlewares to the
// gRPC server interceptors.
func AppendMetricsMiddlewares(log *slog.Logger, uu []grpc.UnaryServerInterceptor, ss []grpc.StreamServerInterceptor) ([]grpc.UnaryServerInterceptor, []grpc.StreamServerInterceptor, error) {
	log.Debug("registering gRPC metrics interceptors")
	metrics := prometheus.NewServerMetrics(prometheus.WithServerHandlingTimeHistogram())
	uu = append(uu, metrics.UnaryServerInterceptor())
	ss = append(ss, metrics.StreamServerInterceptor())
	if err := promapi.Register(metrics); err != nil {
		return nil, nil, err
	}
	return uu, ss, nil
}
