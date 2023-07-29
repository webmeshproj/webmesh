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

package services

import (
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
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/plugins/basicauth"
	"github.com/webmeshproj/webmesh/pkg/plugins/ldap"
	"github.com/webmeshproj/webmesh/pkg/services/dashboard"
	"github.com/webmeshproj/webmesh/pkg/services/leaderproxy"
	"github.com/webmeshproj/webmesh/pkg/util"
)

const (
	ListenAddressEnvVar = "SERVICES_LISTEN_ADDRESS"
	CertFileEnvVar      = "SERVICES_TLS_CERT_FILE"
	KeyFileEnvVar       = "SERVICES_TLS_KEY_FILE"
	InsecureEnvVar      = "SERVICES_INSECURE"
)

// Options contains the configuration for the gRPC server.
type Options struct {
	// ListenAddress is the address to listen on.
	ListenAddress string `json:"listen-address,omitempty" yaml:"listen-address,omitempty" toml:"listen-address,omitempty"`
	// TLSCertFile is the path to the TLS certificate file.
	TLSCertFile string `json:"tls-cert-file,omitempty" yaml:"tls-cert-file,omitempty" toml:"tls-cert-file,omitempty"`
	// TLSKeyFile is the path to the TLS key file.
	TLSKeyFile string `json:"tls-key-file,omitempty" yaml:"tls-key-file,omitempty" toml:"tls-key-file,omitempty"`
	// Insecure is true if the transport is insecure.
	Insecure bool `json:"insecure,omitempty" yaml:"insecure,omitempty" toml:"insecure,omitempty"`
	// API options
	API *APIOptions `json:"api,omitempty" yaml:"api,omitempty" toml:"api,omitempty"`
	// MeshDNS options
	MeshDNS *MeshDNSOptions `json:"mesh-dns,omitempty" yaml:"mesh-dns,omitempty" toml:"mesh-dns,omitempty"`
	// TURN options
	TURN *TURNOptions `json:"turn,omitempty" yaml:"turn,omitempty" toml:"turn,omitempty"`
	// Metrics options
	Metrics *MetricsOptions `json:"metrics,omitempty" yaml:"metrics,omitempty" toml:"metrics,omitempty"`
	// Dashboard options
	Dashboard *dashboard.Options `json:"dashboard,omitempty" yaml:"dashboard,omitempty" toml:"dashboard,omitempty"`
}

// NewOptions returns new Options with sensible defaults.
func NewOptions() *Options {
	return &Options{
		ListenAddress: ":8443",
		API:           NewAPIOptions(),
		MeshDNS:       NewMeshDNSOptions(),
		TURN:          NewTURNOptions(),
		Metrics:       NewMetricsOptions(),
		Dashboard:     dashboard.NewOptions(),
	}
}

// BindFlags binds the gRPC options to the given flag set.
func (o *Options) BindFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.ListenAddress, "services.listen-address", util.GetEnvDefault(ListenAddressEnvVar, ":8443"),
		"gRPC server listen address.")
	fs.StringVar(&o.TLSCertFile, "services.tls-cert-file", util.GetEnvDefault(CertFileEnvVar, ""),
		"gRPC server TLS certificate file.")
	fs.StringVar(&o.TLSKeyFile, "services.tls-key-file", util.GetEnvDefault(KeyFileEnvVar, ""),
		"gRPC server TLS key file.")
	fs.BoolVar(&o.Insecure, "services.insecure", util.GetEnvDefault(InsecureEnvVar, "false") == "true",
		"Don't use TLS for the gRPC server.")

	o.API.BindFlags(fs)
	o.MeshDNS.BindFlags(fs)
	o.TURN.BindFlags(fs)
	o.Metrics.BindFlags(fs)
	o.Dashboard.BindFlags(fs)
}

// Validate validates the options.
func (o *Options) Validate() error {
	if o.ListenAddress == "" {
		return fmt.Errorf("listen address must be specified")
	}
	if !o.Insecure {
		if o.TLSCertFile == "" {
			return fmt.Errorf("TLS certificate file must be specified")
		}
		if o.TLSKeyFile == "" {
			return fmt.Errorf("TLS key file must be specified")
		}
	}
	if o.API == nil {
		o.API = NewAPIOptions()
	}
	if o.MeshDNS == nil {
		o.MeshDNS = NewMeshDNSOptions()
	}
	if o.TURN == nil {
		o.TURN = NewTURNOptions()
	}
	if o.Metrics == nil {
		o.Metrics = NewMetricsOptions()
	}
	if o.Dashboard == nil {
		o.Dashboard = dashboard.NewOptions()
	}
	if err := o.API.Validate(); err != nil {
		return err
	}
	if err := o.MeshDNS.Validate(); err != nil {
		return err
	}
	if err := o.TURN.Validate(); err != nil {
		return err
	}
	return nil
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
func (o *Options) ServerOptions(store mesh.Mesh, log *slog.Logger) (srvrOptions []grpc.ServerOption, proxyOptions []grpc.DialOption, err error) {
	var opts []grpc.ServerOption
	if !o.Insecure {
		tlsConfig, err := o.TLSConfig()
		if err != nil {
			return nil, nil, err
		}
		// Bit of a hack, but if we are using the mTLS plugin, we need to make sure
		// the server requests a client certificate.
		if _, ok := store.Plugins().Get("mtls"); ok {
			tlsConfig.ClientAuth = tls.RequestClientCert
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.Creds(insecure.NewCredentials()))
	}
	unarymiddlewares := []grpc.UnaryServerInterceptor{
		context.LogInjectUnaryServerInterceptor(log),
		logging.UnaryServerInterceptor(InterceptorLogger(), logging.WithLogOnEvents(logging.StartCall, logging.FinishCall)),
	}
	streammiddlewares := []grpc.StreamServerInterceptor{
		context.LogInjectStreamServerInterceptor(log),
		logging.StreamServerInterceptor(InterceptorLogger(), logging.WithLogOnEvents(logging.StartCall, logging.FinishCall)),
	}
	if o.Metrics.Enabled {
		log.Debug("registering gRPC metrics interceptors")
		metrics := prometheus.NewServerMetrics(prometheus.WithServerHandlingTimeHistogram())
		unarymiddlewares = append(unarymiddlewares, metrics.UnaryServerInterceptor())
		streammiddlewares = append(streammiddlewares, metrics.StreamServerInterceptor())
		if err := promapi.Register(metrics); err != nil {
			return nil, nil, err
		}
	}
	if store.Plugins().HasAuth() {
		log.Debug("registering auth interceptor")
		unarymiddlewares = append(unarymiddlewares, store.Plugins().AuthUnaryInterceptor())
		streammiddlewares = append(streammiddlewares, store.Plugins().AuthStreamInterceptor())
	}
	proxyTLS, err := o.ProxyTLSConfig()
	if err != nil {
		return nil, nil, err
	}
	var proxyCreds []grpc.DialOption
	if proxyTLS != nil {
		proxyCreds = append(proxyCreds, grpc.WithTransportCredentials(credentials.NewTLS(proxyTLS)))
	} else {
		proxyCreds = append(proxyCreds, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	if o.API.ProxyAuth != nil {
		if o.API.ProxyAuth.Basic != nil {
			proxyCreds = append(proxyCreds, basicauth.NewCreds(o.API.ProxyAuth.Basic.Username, o.API.ProxyAuth.Basic.Password))
		}
		if o.API.ProxyAuth.LDAP != nil {
			proxyCreds = append(proxyCreds, ldap.NewCreds(o.API.ProxyAuth.LDAP.Username, o.API.ProxyAuth.LDAP.Password))
		}
	}
	if !o.API.DisableLeaderProxy {
		log.Debug("registering leader proxy interceptors")
		leaderProxy := leaderproxy.New(store, proxyCreds)
		unarymiddlewares = append(unarymiddlewares, leaderProxy.UnaryInterceptor())
		streammiddlewares = append(streammiddlewares, leaderProxy.StreamInterceptor())
	}
	opts = append(opts, grpc.ChainUnaryInterceptor(unarymiddlewares...))
	opts = append(opts, grpc.ChainStreamInterceptor(streammiddlewares...))
	return opts, proxyCreds, nil
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
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	return config, nil
}

// ProxyTLSConfig returns the TLS configuration for proxying.
func (o *Options) ProxyTLSConfig() (*tls.Config, error) {
	if o.API.ProxyInsecure {
		return nil, nil
	}
	var config tls.Config
	if o.API.ProxyAuth != nil && o.API.ProxyAuth.MTLS != nil {
		cert, err := tls.LoadX509KeyPair(o.API.ProxyAuth.MTLS.CertFile, o.API.ProxyAuth.MTLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load x509 key pair: %w", err)
		}
		config.Certificates = []tls.Certificate{cert}
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		slog.Default().Warn("failed to load system cert pool", slog.String("error", err.Error()))
		pool = x509.NewCertPool()
	}
	if o.API.ProxyTLSCAFile != "" {
		ca, err := os.ReadFile(o.API.ProxyTLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file: %w", err)
		}
		if ok := pool.AppendCertsFromPEM(ca); !ok {
			return nil, fmt.Errorf("append certs from pem")
		}
	}
	config.RootCAs = pool
	if o.API.ProxyVerifyChainOnly {
		config.InsecureSkipVerify = true
		config.VerifyPeerCertificate = util.VerifyChainOnly
	} else if o.API.ProxyInsecureSkipVerify {
		config.InsecureSkipVerify = true
	}
	return &config, nil
}

// ToFeatureSet converts the options to a feature set.
func (o *Options) ToFeatureSet() []v1.Feature {
	features := []v1.Feature{v1.Feature_NODES}
	if !o.API.DisableLeaderProxy {
		features = append(features, v1.Feature_LEADER_PROXY)
	}
	if o.API.Mesh {
		features = append(features, v1.Feature_MESH_API)
	}
	if o.API.Admin {
		features = append(features, v1.Feature_ADMIN_API)
	}
	if o.API.PeerDiscovery {
		features = append(features, v1.Feature_PEER_DISCOVERY)
	}
	if o.API.WebRTC {
		features = append(features, v1.Feature_ICE_NEGOTIATION)
	}
	if o.Metrics.Enabled {
		features = append(features, v1.Feature_METRICS)
	}
	if o.TURN.Enabled {
		features = append(features, v1.Feature_TURN_SERVER)
	}
	if o.MeshDNS.Enabled {
		features = append(features, v1.Feature_MESH_DNS)
	}
	return features
}

// InterceptorLogger returns a logging.Logger that logs to the given slog.Logger.
func InterceptorLogger() logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		context.LoggerFrom(ctx).Log(ctx, slog.Level(lvl), msg, fields...)
	})
}
