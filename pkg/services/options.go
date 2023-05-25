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
	"errors"
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
	ListenAddressEnvVar           = "GRPC_LISTEN_ADDRESS"
	CertFileEnvVar                = "GRPC_TLS_CERT_FILE"
	KeyFileEnvVar                 = "GRPC_TLS_KEY_FILE"
	CAFileEnvVar                  = "GRPC_TLS_CA_FILE"
	ClientCAFileEnvVar            = "GRPC_TLS_CLIENT_CA_FILE"
	MTLSEnvVar                    = "GRPC_MTLS"
	SkipVerifyHostnameEnvVar      = "GRPC_SKIP_VERIFY_HOSTNAME"
	InsecureEnvVar                = "GRPC_INSECURE"
	EnableMetricsEnvVar           = "GRPC_ENABLE_METRICS"
	MetricsListenAddressEnvVar    = "GRPC_METRICS_LISTEN_ADDRESS"
	MetricsPathEnvVar             = "GRPC_METRICS_PATH"
	DisableLeaderProxyEnvVar      = "GRPC_DISABLE_LEADER_PROXY"
	EnableMeshAPIEnvVar           = "GRPC_ENABLE_MESH_API"
	EnableWebRTCAPIEnvVar         = "GRPC_ENABLE_WEBRTC_API"
	STUNServersEnvVar             = "GRPC_STUN_SERVERS"
	EnableTURNServerEnvVar        = "GRPC_ENABLE_TURN_SERVER"
	TURNServerEndpointEnvVar      = "GRPC_TURN_SERVER_ENDPOINT"
	TURNServerPublicIPEnvVar      = "GRPC_TURN_SERVER_PUBLIC_IP"
	TURNServerListenAddressEnvVar = "GRPC_TURN_SERVER_LISTEN_ADDRESS"
	TURNServerPortEnvVar          = "GRPC_TURN_SERVER_PORT"
	TURNServerRealmEnvVar         = "GRPC_TURN_SERVER_REALM"
	STUNPortRangeEnvVar           = "GRPC_STUN_PORT_RANGE"
	ExclusiveTURNServerEnvVar     = "GRPC_EXCLUSIVE_TURN_SERVER"
)

// Options contains the configuration for the gRPC server.
type Options struct {
	// ListenAddress is the address to listen on.
	ListenAddress string `json:"listen-address" yaml:"listen-address" toml:"listen-address"`
	// TLSCertFile is the path to the TLS certificate file.
	TLSCertFile string `json:"tls-cert-file" yaml:"tls-cert-file" toml:"tls-cert-file"`
	// TLSKeyFile is the path to the TLS key file.
	TLSKeyFile string `json:"tls-key-file" yaml:"tls-key-file" toml:"tls-key-file"`
	// TLSCAFile is the path to the TLS CA file. If not set, client
	// authentication is disabled.
	TLSCAFile string `json:"tls-ca-file" yaml:"tls-ca-file" toml:"tls-ca-file"`
	// TLSClientCAFile is the path to the TLS client CA file.
	// If empty, either TLSCAFile or the system CA pool is used.
	TLSClientCAFile string `json:"tls-client-ca-file" yaml:"tls-client-ca-file" toml:"tls-client-ca-file"`
	// MTLS is true if mutual TLS is enabled.
	MTLS bool `json:"mtls" yaml:"mtls" toml:"mtls"`
	// SkipVerifyHostname is true if the hostname should not be verified.
	SkipVerifyHostname bool `json:"skip-verify-hostname" yaml:"skip-verify-hostname" toml:"skip-verify-hostname"`
	// Insecure is true if the transport is insecure.
	Insecure bool `json:"insecure" yaml:"insecure" toml:"insecure"`
	// EnableMetrics is true if metrics should be enabled.
	EnableMetrics bool `json:"enable-metrics" yaml:"enable-metrics" toml:"enable-metrics"`
	// MetricsListenAddress is the address to listen on for metrics.
	MetricsListenAddress string `json:"metrics-listen-address" yaml:"metrics-listen-address" toml:"metrics-listen-address"`
	// MetricsPath is the path to serve metrics on.
	MetricsPath string `json:"metrics-path" yaml:"metrics-path" toml:"metrics-path"`
	// DisableLeaderProxy disables the leader proxy.
	DisableLeaderProxy bool `json:"disable-leader-proxy" yaml:"disable-leader-proxy" toml:"disable-leader-proxy"`
	// EnableMeshAPI enables the mesh API.
	EnableMeshAPI bool `json:"enable-mesh-api" yaml:"enable-mesh-api" toml:"enable-mesh-api"`
	// EnableWebRTCAPI enables the WebRTC API.
	EnableWebRTCAPI bool `json:"enable-webrtc-api" yaml:"enable-webrtc-api" toml:"enable-webrtc-api"`
	// STUNServers is a list of STUN servers to use. Required
	// if the WebRTC API is enabled and the TURN server is disabled.
	STUNServers string `json:"stun-servers" yaml:"stun-servers" toml:"stun-servers"`
	// EnableTURNServer enables the TURN server.
	EnableTURNServer bool `json:"enable-turn-server" yaml:"enable-turn-server" toml:"enable-turn-server"`
	// TURNServerEndpoint is the endpoint to advertise for the TURN server.
	// If empty, the public IP and server port is used.
	TURNServerEndpoint string `json:"turn-server-endpoint" yaml:"turn-server-endpoint" toml:"turn-server-endpoint"`
	// TURNServerPublicIP is the address advertised for STUN requests.
	TURNServerPublicIP string `json:"turn-server-public-ip" yaml:"turn-server-public-ip" toml:"turn-server-public-ip"`
	// TURNServerListenAddress is the address to listen on for TURN connections.
	TURNServerListenAddress string `json:"turn-server-listen-address" yaml:"turn-server-listen-address" toml:"turn-server-listen-address"`
	// TURNServerPort is the port to listen on for TURN connections.
	TURNServerPort int `json:"turn-server-port" yaml:"turn-server-port" toml:"turn-server-port"`
	// TURNServerRealm is the realm used for TURN server authentication.
	TURNServerRealm string `json:"turn-server-realm" yaml:"turn-server-realm" toml:"turn-server-realm"`
	// STUNPortRange is the port range to use for STUN.
	STUNPortRange string `json:"stun-port-range" yaml:"stun-port-range" toml:"stun-port-range"`
	// ExclusiveTURNServer will replace all STUNServers with the local TURN server.
	ExclusiveTURNServer bool `json:"exclusive-turn-server" yaml:"exclusive-turn-server" toml:"exclusive-turn-server"`
}

// NewOptions returns new Options with sensible defaults.
func NewOptions() *Options {
	return &Options{
		ListenAddress:           ":8443",
		MetricsListenAddress:    ":8080",
		MetricsPath:             "/metrics",
		STUNServers:             "stun:stun.l.google.com:19302",
		TURNServerListenAddress: "0.0.0.0",
		TURNServerPort:          3478,
		TURNServerRealm:         "webmesh.io",
		STUNPortRange:           "49152-65535",
	}
}

// BindFlags binds the gRPC options to the given flag set.
func (o *Options) BindFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.ListenAddress, "grpc.listen-address", util.GetEnvDefault(ListenAddressEnvVar, ":8443"),
		"gRPC server listen address.")
	fs.StringVar(&o.TLSCertFile, "grpc.tls-cert-file", util.GetEnvDefault(CertFileEnvVar, ""),
		"gRPC server TLS certificate file.")
	fs.StringVar(&o.TLSKeyFile, "grpc.tls-key-file", util.GetEnvDefault(KeyFileEnvVar, ""),
		"gRPC server TLS key file.")
	fs.StringVar(&o.TLSCAFile, "grpc.tls-ca-file", util.GetEnvDefault(CAFileEnvVar, ""),
		"gRPC server TLS CA file.")
	fs.StringVar(&o.TLSClientCAFile, "grpc.tls-client-ca-file", util.GetEnvDefault(ClientCAFileEnvVar, ""),
		"gRPC server TLS client CA file.")
	fs.BoolVar(&o.MTLS, "grpc.mtls", util.GetEnvDefault(MTLSEnvVar, "false") == "true",
		"Enable mutual TLS.")
	fs.BoolVar(&o.SkipVerifyHostname, "grpc.skip-verify-hostname", util.GetEnvDefault(SkipVerifyHostnameEnvVar, "false") == "true",
		"Skip hostname verification.")
	fs.BoolVar(&o.Insecure, "grpc.insecure", util.GetEnvDefault(InsecureEnvVar, "false") == "true",
		"Don't use TLS for the gRPC server.")
	fs.BoolVar(&o.EnableMetrics, "grpc.enable-metrics", util.GetEnvDefault(EnableMetricsEnvVar, "false") == "true",
		"Enable gRPC metrics.")
	fs.StringVar(&o.MetricsListenAddress, "grpc.metrics-listen-address", util.GetEnvDefault(MetricsListenAddressEnvVar, ":8080"),
		"gRPC metrics listen address.")
	fs.StringVar(&o.MetricsPath, "grpc.metrics-path", util.GetEnvDefault(MetricsPathEnvVar, "/metrics"),
		"gRPC metrics path.")
	fs.BoolVar(&o.DisableLeaderProxy, "grpc.disable-leader-proxy", util.GetEnvDefault(DisableLeaderProxyEnvVar, "false") == "true",
		"Disable the leader proxy.")
	fs.BoolVar(&o.EnableMeshAPI, "grpc.enable-mesh-api", util.GetEnvDefault(EnableMeshAPIEnvVar, "false") == "true",
		"Enable the mesh API.")
	fs.BoolVar(&o.EnableWebRTCAPI, "grpc.enable-webrtc-api", util.GetEnvDefault(EnableWebRTCAPIEnvVar, "false") == "true",
		"Enable the WebRTC API.")
	fs.StringVar(&o.STUNServers, "grpc.stun-servers", util.GetEnvDefault(STUNServersEnvVar, "stun:stun.l.google.com:19302"),
		"STUN servers to use.")
	fs.BoolVar(&o.EnableTURNServer, "grpc.enable-turn-server", util.GetEnvDefault(EnableTURNServerEnvVar, "false") == "true",
		"Enable the TURN server.")
	fs.StringVar(&o.TURNServerEndpoint, "grpc.turn-server-endpoint", util.GetEnvDefault(TURNServerEndpointEnvVar, ""),
		"The TURN server endpoint. If empty, the public IP will be used.")
	fs.StringVar(&o.TURNServerPublicIP, "grpc.turn-server-public-ip", util.GetEnvDefault(TURNServerPublicIPEnvVar, ""),
		"The address advertised for STUN requests.")
	fs.StringVar(&o.TURNServerListenAddress, "grpc.turn-server-listen-address", util.GetEnvDefault(TURNServerListenAddressEnvVar, "0.0.0.0"),
		"Address to listen on for TURN connections.")
	fs.IntVar(&o.TURNServerPort, "grpc.turn-server-port", util.GetEnvIntDefault(TURNServerPortEnvVar, 3478),
		"Port to listen on for TURN connections.")
	fs.StringVar(&o.TURNServerRealm, "grpc.turn-server-realm", util.GetEnvDefault(TURNServerRealmEnvVar, "webmesh.io"),
		"Realm used for TURN server authentication.")
	fs.StringVar(&o.STUNPortRange, "grpc.stun-port-range", util.GetEnvDefault(STUNPortRangeEnvVar, "49152-65535"),
		"Port range to use for STUN.")
	fs.BoolVar(&o.ExclusiveTURNServer, "grpc.exclusive-turn-server", util.GetEnvDefault(ExclusiveTURNServerEnvVar, "false") == "true",
		"Replace all STUNServers with the local TURN server. The equivalent of --grpc.stun-servers=stun:<public-ip>:<port>.")
}

// Validate validates the options.
func (o *Options) Validate() error {
	if o.Insecure && o.MTLS {
		return errors.New("cannot use both insecure and mutual TLS")
	}
	if o.EnableTURNServer && o.TURNServerPublicIP == "" {
		return errors.New("must specify a public IP for the TURN server")
	}
	if o.EnableTURNServer && o.TURNServerPort <= 0 {
		return errors.New("must specify a port for the TURN server")
	}
	if o.EnableTURNServer && o.STUNPortRange == "" {
		return errors.New("must specify STUN port range")
	}
	if o.EnableWebRTCAPI && !o.EnableTURNServer {
		if o.STUNServers == "" {
			return errors.New("must specify STUN servers")
		}
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
func (o *Options) ServerOptions(store store.Store) ([]grpc.ServerOption, *tls.Config, error) {
	var opts []grpc.ServerOption
	var tlsConfig *tls.Config
	var err error
	if !o.Insecure {
		tlsConfig, err = o.TLSConfig()
		if err != nil {
			return nil, nil, err
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
	return opts, tlsConfig, nil
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
