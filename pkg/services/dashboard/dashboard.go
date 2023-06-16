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

// Package dashboard contains a service that serves a web dashboard.
// nolint
package dashboard

import (
	"crypto/tls"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"

	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/util"
)

//go:generate bash -exc "cd app; yarn ; VERSION=`git describe --tags --always --dirty` yarn build"
//go:embed app/dist/spa
var staticFiles embed.FS

const (
	DashboardEnabledEnvVar = "SERVICES_DASHBOARD_ENABLED"
	DashboardListenEnvVar  = "SERVICES_DASHBOARD_LISTEN_ADDRESS"
	DashboardTLSCertEnvVar = "SERVICES_DASHBOARD_TLS_CERT_FILE"
	DashboardTLSKeyEnvVar  = "SERVICES_DASHBOARD_TLS_KEY_FILE"
	DashboardPrefixEnvVar  = "SERVICES_DASHBOARD_PREFIX"
)

// Options contains the options for the dashboard service.
type Options struct {
	// Enabled is whether the dashboard is enabled.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty" toml:"enabled,omitempty"`
	// ListenAddress is the address to listen on.
	ListenAddress string `json:"listen-address,omitempty" yaml:"listen-address,omitempty" toml:"listen-address,omitempty"`
	// TLSCertFile is the path to a certificate file to use for TLS.
	TLSCertFile string `json:"tls-cert-file,omitempty" yaml:"tls-cert-file,omitempty" toml:"tls-cert-file,omitempty"`
	// TLSKeyFile is the path to a key file to use for TLS.
	TLSKeyFile string `json:"tls-key-file,omitempty" yaml:"tls-key-file,omitempty" toml:"tls-key-file,omitempty"`
	// Prefix is the prefix to use for the dashboard.
	Prefix string `json:"prefix,omitempty" yaml:"prefix,omitempty" toml:"prefix,omitempty"`
}

// BindFlags binds the options to a flag set.
func (o *Options) BindFlags(fs *flag.FlagSet) {
	fs.BoolVar(&o.Enabled, "services.dashboard.enabled", util.GetEnvDefault(DashboardEnabledEnvVar, "false") == "true",
		"Enable the web dashboard.")
	fs.StringVar(&o.ListenAddress, "services.dashboard.listen-address", util.GetEnvDefault(DashboardListenEnvVar, ":8080"),
		"The address for the dashboard to listen on.")
	fs.StringVar(&o.TLSCertFile, "services.dashboard.tls-cert-file", util.GetEnvDefault(DashboardTLSCertEnvVar, ""),
		"The path to a certificate file to use for TLS.")
	fs.StringVar(&o.TLSKeyFile, "services.dashboard.tls-key-file", util.GetEnvDefault(DashboardTLSKeyEnvVar, ""),
		"The path to a key file to use for TLS.")
	fs.StringVar(&o.Prefix, "services.dashboard.prefix", util.GetEnvDefault(DashboardPrefixEnvVar, "/"),
		"The path prefix to use for the dashboard.")
}

// NewOptions creates a new Options with default values.
func NewOptions() *Options {
	return &Options{
		Enabled:       false,
		ListenAddress: ":8080",
		Prefix:        "/",
	}
}

// NewServer returns a new Dashboard Server.
func NewServer(backend *grpc.Server, opts *Options) (*Server, error) {
	log := slog.Default().With("component", "dashboard")
	mux := http.NewServeMux()
	root := strings.TrimSuffix(opts.Prefix, "/")
	apiRoot := fmt.Sprintf("%s/api/", root)
	staticRoot, err := fs.Sub(staticFiles, "app/dist/spa")
	if err != nil {
		return nil, fmt.Errorf("get static subdirectory: %w", err)
	}
	mux.Handle(apiRoot, http.StripPrefix(apiRoot, grpcweb.WrapServer(backend)))
	mux.Handle(root+"/", http.FileServer(http.FS(staticRoot)))
	srvr := &http.Server{
		Addr:    opts.ListenAddress,
		Handler: logRequest(mux),
		BaseContext: func(_ net.Listener) context.Context {
			return context.WithLogger(context.Background(), log)
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			log := context.LoggerFrom(ctx).With("remote", c.RemoteAddr().String())
			return context.WithLogger(ctx, log)
		},
	}
	if opts.TLSCertFile != "" && opts.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(opts.TLSCertFile, opts.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load key pair: %w", err)
		}
		srvr.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}
	return &Server{srvr}, nil
}

type Server struct {
	*http.Server
}

func (s *Server) ListenAndServe() error {
	if s.TLSConfig != nil {
		return s.Server.ListenAndServeTLS("", "")
	}
	return s.Server.ListenAndServe()
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := context.LoggerFrom(r.Context())
		log.Info("request", "method", r.Method, "url", r.URL.String())
		next.ServeHTTP(w, r)
	})
}
