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

package services

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	promapi "github.com/prometheus/client_golang/prometheus"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"gitlab.com/webmesh/node/pkg/services/leaderproxy"
	"gitlab.com/webmesh/node/pkg/store"
	"gitlab.com/webmesh/node/pkg/util"
)

const (
	GRPCListenAddressEnvVar        = "GRPC_LISTEN_ADDRESS"
	GRPCCertFileEnvVar             = "GRPC_TLS_CERT_FILE"
	GRPCKeyFileEnvVar              = "GRPC_TLS_KEY_FILE"
	GRPCCAFileEnvVar               = "GRPC_TLS_CA_FILE"
	GRPCClientCAFileEnvVar         = "GRPC_TLS_CLIENT_CA_FILE"
	GRPCMTLSEnvVar                 = "GRPC_MTLS"
	GRPCSkipVerifyHostnameEnvVar   = "GRPC_SKIP_VERIFY_HOSTNAME"
	GRPCInsecureEnvVar             = "GRPC_INSECURE"
	GRPCEnableMetricsEnvVar        = "GRPC_ENABLE_METRICS"
	GRPCMetricsListenAddressEnvVar = "GRPC_METRICS_LISTEN_ADDRESS"
	GRPCMetricsPathEnvVar          = "GRPC_METRICS_PATH"
	GRPCDisableLeaderProxyEnvVar   = "GRPC_DISABLE_LEADER_PROXY"
)

// Options contains the configuration for the gRPC server.
type Options struct {
	// ListenAddress is the address to listen on.
	ListenAddress string
	// TLSCertFile is the path to the TLS certificate file.
	TLSCertFile string
	// TLSKeyFile is the path to the TLS key file.
	TLSKeyFile string
	// TLSCAFile is the path to the TLS CA file. If not set, client
	// authentication is disabled.
	TLSCAFile string
	// TLSClientCAFile is the path to the TLS client CA file.
	// If empty, either TLSCAFile or the system CA pool is used.
	TLSClientCAFile string
	// MTLS is true if mutual TLS is enabled.
	MTLS bool
	// SkipVerifyHostname is true if the hostname should not be verified.
	SkipVerifyHostname bool
	// Insecure is true if the transport is insecure.
	Insecure bool
	// EnableMetrics is true if metrics should be enabled.
	EnableMetrics bool
	// MetricsListenAddress is the address to listen on for metrics.
	MetricsListenAddress string
	// MetricsPath is the path to serve metrics on.
	MetricsPath string
	// DisableLeaderProxy disables the leader proxy.
	DisableLeaderProxy bool
}

// NewOptions returns new Options with sensible defaults.
func NewOptions() *Options {
	return &Options{
		ListenAddress:        ":8443",
		MetricsListenAddress: ":8080",
		MetricsPath:          "/metrics",
	}
}

// BindFlags binds the gRPC options to the given flag set.
func (o *Options) BindFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.ListenAddress, "grpc.listen-address", util.GetEnvDefault(GRPCListenAddressEnvVar, ":8443"),
		"gRPC server listen address.")
	fs.StringVar(&o.TLSCertFile, "grpc.tls-cert-file", util.GetEnvDefault(GRPCCertFileEnvVar, ""),
		"gRPC server TLS certificate file.")
	fs.StringVar(&o.TLSKeyFile, "grpc.tls-key-file", util.GetEnvDefault(GRPCKeyFileEnvVar, ""),
		"gRPC server TLS key file.")
	fs.StringVar(&o.TLSCAFile, "grpc.tls-ca-file", util.GetEnvDefault(GRPCCAFileEnvVar, ""),
		"gRPC server TLS CA file.")
	fs.StringVar(&o.TLSClientCAFile, "grpc.tls-client-ca-file", util.GetEnvDefault(GRPCClientCAFileEnvVar, ""),
		"gRPC server TLS client CA file.")
	fs.BoolVar(&o.MTLS, "grpc.mtls", util.GetEnvDefault(GRPCMTLSEnvVar, "false") == "true",
		"Enable mutual TLS.")
	fs.BoolVar(&o.SkipVerifyHostname, "grpc.skip-verify-hostname", util.GetEnvDefault(GRPCSkipVerifyHostnameEnvVar, "false") == "true",
		"Skip hostname verification.")
	fs.BoolVar(&o.Insecure, "grpc.insecure", util.GetEnvDefault(GRPCInsecureEnvVar, "false") == "true",
		"Don't use TLS for the gRPC server.")
	fs.BoolVar(&o.EnableMetrics, "grpc.enable-metrics", util.GetEnvDefault(GRPCEnableMetricsEnvVar, "false") == "true",
		"Enable gRPC metrics.")
	fs.StringVar(&o.MetricsListenAddress, "grpc.metrics-listen-address", util.GetEnvDefault(GRPCMetricsListenAddressEnvVar, ":8080"),
		"gRPC metrics listen address.")
	fs.StringVar(&o.MetricsPath, "grpc.metrics-path", util.GetEnvDefault(GRPCMetricsPathEnvVar, "/metrics"),
		"gRPC metrics path.")
	fs.BoolVar(&o.DisableLeaderProxy, "grpc.disable-leader-proxy", util.GetEnvDefault(GRPCDisableLeaderProxyEnvVar, "false") == "true",
		"Disable the leader proxy.")
}

// ListenPort returns the port the options are configured to listen on.
func (o *Options) ListenPort() (int, error) {
	_, port, err := net.SplitHostPort(o.ListenAddress)
	if err != nil {
		return 0, err
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return 0, err
	}
	return portNum, nil
}

// ServerOptions converts the options to gRPC server options.
func (o *Options) ServerOptions(store store.Store) ([]grpc.ServerOption, error) {
	var opts []grpc.ServerOption
	var tlsConfig *tls.Config
	var err error
	if !o.Insecure {
		tlsConfig, err = o.TLSConfig()
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.Creds(insecure.NewCredentials()))
	}
	unarymiddlewares := []grpc.UnaryServerInterceptor{
		logging.UnaryServerInterceptor(InterceptorLogger(slog.Default().With("component", "grpc")),
			logging.WithLogOnEvents(logging.StartCall, logging.FinishCall)),
	}
	streammiddlewares := []grpc.StreamServerInterceptor{
		logging.StreamServerInterceptor(InterceptorLogger(slog.Default().With("component", "grpc")),
			logging.WithLogOnEvents(logging.StartCall, logging.FinishCall)),
	}
	if o.EnableMetrics {
		slog.Default().Debug("registering gRPC metrics interceptors")
		metrics := prometheus.NewServerMetrics(prometheus.WithServerHandlingTimeHistogram())
		unarymiddlewares = append(unarymiddlewares, metrics.UnaryServerInterceptor())
		streammiddlewares = append(streammiddlewares, metrics.StreamServerInterceptor())
		promapi.MustRegister(metrics)
	}
	if !o.DisableLeaderProxy {
		slog.Default().Debug("registering leader proxy interceptors")
		proxyLogger := slog.Default().With("component", "leader-proxy")
		leaderProxy := leaderproxy.New(store, tlsConfig, proxyLogger)
		unarymiddlewares = append(unarymiddlewares, leaderProxy.UnaryInterceptor())
		streammiddlewares = append(streammiddlewares, leaderProxy.StreamInterceptor())
	}
	opts = append(opts, grpc.ChainUnaryInterceptor(unarymiddlewares...))
	opts = append(opts, grpc.ChainStreamInterceptor(streammiddlewares...))
	return opts, nil
}

// TLSConfig returns the TLS configuration.
func (o *Options) TLSConfig() (*tls.Config, error) {
	if o.Insecure {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(o.TLSCertFile, o.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load x509 key pair: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err == nil {
		slog.Default().Warn("failed to load system cert pool", slog.String("error", err.Error()))
		pool = x509.NewCertPool()
	}
	clientPool := pool.Clone()
	if o.TLSCAFile != "" {
		ca, err := os.ReadFile(o.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file: %w", err)
		}
		if ok := pool.AppendCertsFromPEM(ca); !ok {
			return nil, fmt.Errorf("append certs from pem")
		}
	}
	if o.TLSClientCAFile != "" {
		ca, err := os.ReadFile(o.TLSClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client ca file: %w", err)
		}
		if ok := clientPool.AppendCertsFromPEM(ca); !ok {
			return nil, fmt.Errorf("append certs from pem")
		}
	}
	var clientAuth tls.ClientAuthType
	if o.MTLS {
		clientAuth = tls.RequireAndVerifyClientCert
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ClientCAs:    clientPool,
		ClientAuth:   clientAuth,
	}
	if o.SkipVerifyHostname {
		config.VerifyPeerCertificate = util.VerifyChainOnly
	}
	return config, nil
}

// InterceptorLogger returns a logging.Logger that logs to the given slog.Logger.
func InterceptorLogger(l *slog.Logger) logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		l.Log(ctx, slog.Level(lvl), msg, fields...)
	})
}
