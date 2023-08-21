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
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/util/envutil"
)

//go:generate bash ../../../web/dashboard/embed.sh
//go:embed static/**
var staticFiles embed.FS

const staticAssetsPath = "static/dashboard"

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
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty" toml:"enabled,omitempty" mapstructure:"enabled,omitempty"`
	// ListenAddress is the address to listen on.
	ListenAddress string `json:"listen-address,omitempty" yaml:"listen-address,omitempty" toml:"listen-address,omitempty" mapstructure:"listen-address,omitempty"`
	// TLSCertFile is the path to a certificate file to use for TLS.
	TLSCertFile string `json:"tls-cert-file,omitempty" yaml:"tls-cert-file,omitempty" toml:"tls-cert-file,omitempty" mapstructure:"tls-cert-file,omitempty"`
	// TLSKeyFile is the path to a key file to use for TLS.
	TLSKeyFile string `json:"tls-key-file,omitempty" yaml:"tls-key-file,omitempty" toml:"tls-key-file,omitempty" mapstructure:"tls-key-file,omitempty"`
	// Prefix is the prefix to use for the dashboard.
	Prefix string `json:"prefix,omitempty" yaml:"prefix,omitempty" toml:"prefix,omitempty" mapstructure:"prefix,omitempty"`
}

// BindFlags binds the options to a flag set.
func (o *Options) BindFlags(fs *flag.FlagSet, prefix ...string) {
	var p string
	if len(prefix) > 0 {
		p = strings.Join(prefix, ".") + "."
	}
	fs.BoolVar(&o.Enabled, p+"services.dashboard.enabled", envutil.GetEnvDefault(DashboardEnabledEnvVar, "false") == "true",
		"Enable the web dashboard.")
	fs.StringVar(&o.ListenAddress, p+"services.dashboard.listen-address", envutil.GetEnvDefault(DashboardListenEnvVar, ":8080"),
		"The address for the dashboard to listen on.")
	fs.StringVar(&o.TLSCertFile, p+"services.dashboard.tls-cert-file", envutil.GetEnvDefault(DashboardTLSCertEnvVar, ""),
		"The path to a certificate file to use for TLS.")
	fs.StringVar(&o.TLSKeyFile, p+"services.dashboard.tls-key-file", envutil.GetEnvDefault(DashboardTLSKeyEnvVar, ""),
		"The path to a key file to use for TLS.")
	fs.StringVar(&o.Prefix, p+"services.dashboard.prefix", envutil.GetEnvDefault(DashboardPrefixEnvVar, ""),
		"The path prefix to use for the dashboard.")
}

// DeepCopy returns a deep copy of the options.
func (o *Options) DeepCopy() *Options {
	if o == nil {
		return nil
	}
	no := &Options{}
	*no = *o
	return no
}

// NewOptions creates a new Options with default values.
func NewOptions() *Options {
	return &Options{
		Enabled:       false,
		ListenAddress: ":8080",
	}
}

// NewServer returns a new Dashboard Server.
func NewServer(backend *grpc.Server, opts *Options) (*Server, error) {
	log := slog.Default().With("component", "dashboard")
	mux := http.NewServeMux()
	root := strings.TrimSuffix(opts.Prefix, "/")
	apiRoot := fmt.Sprintf("%s/api/", root)
	staticRoot, err := fs.Sub(staticFiles, staticAssetsPath)
	if err != nil {
		return nil, fmt.Errorf("get static subdirectory: %w", err)
	}
	mux.Handle(apiRoot, http.StripPrefix(apiRoot, grpcweb.WrapServer(backend)))
	if root == "" {
		mux.Handle("/", http.FileServer(http.FS(staticRoot)))
	} else {
		root = root + "/"
		mux.Handle(root, http.StripPrefix(root, http.FileServer(http.FS(staticRoot))))
	}
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
	log := slog.Default()
	if s.TLSConfig != nil {
		log.Info("serving dashboard over TLS", "address", s.Addr)
		return s.Server.ListenAndServeTLS("", "")
	}
	log.Info("serving dashboard over HTTP", "address", s.Addr)
	return s.Server.ListenAndServe()
}

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := context.LoggerFrom(r.Context())
		log.Info("request", "method", r.Method, "url", r.URL.String())
		next.ServeHTTP(w, r)
	})
}
