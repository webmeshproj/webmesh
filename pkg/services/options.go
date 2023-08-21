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
	"flag"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	promapi "github.com/prometheus/client_golang/prometheus"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/services/dashboard"
	"github.com/webmeshproj/webmesh/pkg/services/leaderproxy"
	"github.com/webmeshproj/webmesh/pkg/util/envutil"
)

const (
	ListenAddressEnvVar = "SERVICES_LISTEN_ADDRESS"
	CertFileEnvVar      = "SERVICES_TLS_CERT_FILE"
	KeyFileEnvVar       = "SERVICES_TLS_KEY_FILE"
	InsecureEnvVar      = "SERVICES_INSECURE"

	DefaultGRPCPort = 8443
)

// Options contains the configuration for the gRPC server.
type Options struct {
	// ListenAddress is the address to listen on.
	ListenAddress string `json:"listen-address,omitempty" yaml:"listen-address,omitempty" toml:"listen-address,omitempty" mapstructure:"listen-address,omitempty"`
	// TLSCertFile is the path to the TLS certificate file.
	TLSCertFile string `json:"tls-cert-file,omitempty" yaml:"tls-cert-file,omitempty" toml:"tls-cert-file,omitempty" mapstructure:"tls-cert-file,omitempty"`
	// TLSKeyFile is the path to the TLS key file.
	TLSKeyFile string `json:"tls-key-file,omitempty" yaml:"tls-key-file,omitempty" toml:"tls-key-file,omitempty" mapstructure:"tls-key-file,omitempty"`
	// Insecure is true if the transport is insecure.
	Insecure bool `json:"insecure,omitempty" yaml:"insecure,omitempty" toml:"insecure,omitempty" mapstructure:"insecure,omitempty"`
	// API options
	API *APIOptions `json:"api,omitempty" yaml:"api,omitempty" toml:"api,omitempty" mapstructure:"api,omitempty"`
	// MeshDNS options
	MeshDNS *MeshDNSOptions `json:"mesh-dns,omitempty" yaml:"mesh-dns,omitempty" toml:"mesh-dns,omitempty" mapstructure:"mesh-dns,omitempty"`
	// TURN options
	TURN *TURNOptions `json:"turn,omitempty" yaml:"turn,omitempty" toml:"turn,omitempty" mapstructure:"turn,omitempty"`
	// Metrics options
	Metrics *MetricsOptions `json:"metrics,omitempty" yaml:"metrics,omitempty" toml:"metrics,omitempty" mapstructure:"metrics,omitempty"`
	// Dashboard options
	Dashboard *dashboard.Options `json:"dashboard,omitempty" yaml:"dashboard,omitempty" toml:"dashboard,omitempty" mapstructure:"dashboard,omitempty"`
}

// NewOptions returns new Options with sensible defaults. If grpcPort is 0
// the default port is used.
func NewOptions(grpcPort int) *Options {
	if grpcPort == 0 {
		grpcPort = DefaultGRPCPort
	}
	return &Options{
		ListenAddress: fmt.Sprintf("[::]:%d", grpcPort),
		API:           NewAPIOptions(),
		MeshDNS:       NewMeshDNSOptions(),
		TURN:          NewTURNOptions(),
		Metrics:       NewMetricsOptions(),
		Dashboard:     dashboard.NewOptions(),
	}
}

// BindFlags binds the gRPC options to the given flag set.
func (o *Options) BindFlags(fs *flag.FlagSet, prefix ...string) {
	var p string
	if len(prefix) > 0 {
		p = strings.Join(prefix, ".") + "."
	}
	fs.StringVar(&o.ListenAddress, p+"services.listen-address", envutil.GetEnvDefault(ListenAddressEnvVar, "[::]:8443"),
		"gRPC server listen address.")
	fs.StringVar(&o.TLSCertFile, p+"services.tls-cert-file", envutil.GetEnvDefault(CertFileEnvVar, ""),
		"gRPC server TLS certificate file.")
	fs.StringVar(&o.TLSKeyFile, p+"services.tls-key-file", envutil.GetEnvDefault(KeyFileEnvVar, ""),
		"gRPC server TLS key file.")
	fs.BoolVar(&o.Insecure, p+"services.insecure", envutil.GetEnvDefault(InsecureEnvVar, "false") == "true",
		"Don't use TLS for the gRPC server.")

	o.API.BindFlags(fs, prefix...)
	o.MeshDNS.BindFlags(fs, prefix...)
	o.TURN.BindFlags(fs, prefix...)
	o.Metrics.BindFlags(fs, prefix...)
	o.Dashboard.BindFlags(fs, prefix...)
}

// Validate validates the options.
func (o *Options) Validate() error {
	if o == nil {
		return fmt.Errorf("options are nil")
	}
	if o.ListenAddress == "" {
		return fmt.Errorf("listen address must be specified")
	}
	_, _, err := net.SplitHostPort(o.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen address is invalid: %w", err)
	}
	if !o.Insecure {
		if o.TLSCertFile == "" {
			return fmt.Errorf("TLS certificate file must be specified")
		}
		if o.TLSKeyFile == "" {
			return fmt.Errorf("TLS key file must be specified")
		}
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
func (o *Options) ServerOptions(store mesh.Mesh, log *slog.Logger) (srvrOptions []grpc.ServerOption, err error) {
	var opts []grpc.ServerOption
	if !o.Insecure {
		tlsConfig, err := o.TLSConfig()
		if err != nil {
			return nil, err
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
			return nil, err
		}
	}
	if store.Plugins().HasAuth() {
		log.Debug("registering auth interceptor")
		unarymiddlewares = append(unarymiddlewares, store.Plugins().AuthUnaryInterceptor())
		streammiddlewares = append(streammiddlewares, store.Plugins().AuthStreamInterceptor())
	}
	if !o.API.DisableLeaderProxy {
		log.Debug("registering leader proxy interceptors")
		leaderProxy := leaderproxy.New(store)
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
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	return config, nil
}

// ToFeatureSet converts the options to a feature set.
func (o *Options) ToFeatureSet() []v1.Feature {
	features := []v1.Feature{v1.Feature_NODES}
	if o.API != nil {
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
	}
	if o.Metrics != nil && o.Metrics.Enabled {
		features = append(features, v1.Feature_METRICS)
	}
	if o.TURN != nil && o.TURN.Enabled {
		features = append(features, v1.Feature_TURN_SERVER)
	}
	if o.MeshDNS != nil && o.MeshDNS.Enabled {
		features = append(features, v1.Feature_MESH_DNS)
	}
	return features
}

// DeepCopy returns a deep copy of the options.
func (o *Options) DeepCopy() *Options {
	if o == nil {
		return nil
	}
	deepCopy := *o
	if o.API != nil {
		deepCopy.API = o.API.DeepCopy()
	}
	if o.Metrics != nil {
		deepCopy.Metrics = o.Metrics.DeepCopy()
	}
	if o.MeshDNS != nil {
		deepCopy.MeshDNS = o.MeshDNS.DeepCopy()
	}
	if o.TURN != nil {
		deepCopy.TURN = o.TURN.DeepCopy()
	}
	if o.Dashboard != nil {
		deepCopy.Dashboard = o.Dashboard.DeepCopy()
	}
	return &deepCopy
}

// InterceptorLogger returns a logging.Logger that logs to the given slog.Logger.
func InterceptorLogger() logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		context.LoggerFrom(ctx).Log(ctx, slog.Level(lvl), msg, fields...)
	})
}
