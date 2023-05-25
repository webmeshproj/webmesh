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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	promapi "github.com/prometheus/client_golang/prometheus"
	v1 "gitlab.com/webmesh/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"gitlab.com/webmesh/node/pkg/services/leaderproxy"
	"gitlab.com/webmesh/node/pkg/store"
	"gitlab.com/webmesh/node/pkg/util"
)

const (
	// General options
	ListenAddressEnvVar      = "SERVICES_GRPC_LISTEN_ADDRESS"
	CertFileEnvVar           = "SERVICES_TLS_CERT_FILE"
	KeyFileEnvVar            = "SERVICES_TLS_KEY_FILE"
	CAFileEnvVar             = "SERVICES_TLS_CA_FILE"
	ClientCAFileEnvVar       = "SERVICES_TLS_CLIENT_CA_FILE"
	MTLSEnvVar               = "SERVICES_MTLS"
	SkipVerifyHostnameEnvVar = "SERVICES_SKIP_VERIFY_HOSTNAME"
	InsecureEnvVar           = "SERVICES_INSECURE"

	// Feature flags
	EnableMetricsEnvVar          = "SERVICES_ENABLE_METRICS"
	EnableLeaderProxyEnvVar      = "SERVICES_ENABLE_LEADER_PROXY"
	EnableMeshAPIEnvVar          = "SERVICES_ENABLE_MESH_API"
	EnablePeerDiscoveryAPIEnvVar = "SERVICES_ENABLE_PEER_DISCOVERY_API"
	EnableWebRTCAPIEnvVar        = "SERVICES_ENABLE_WEBRTC_API"
	EnableTURNServerEnvVar       = "SERVICES_ENABLE_TURN_SERVER"
	EnableMeshDNSEnvVar          = "SERVICES_ENABLE_MESH_DNS"

	// Metrics
	MetricsListenAddressEnvVar = "SERVICES_METRICS_LISTEN_ADDRESS"
	MetricsPathEnvVar          = "SERVICES_METRICS_PATH"

	// STUN/TURN
	STUNServersEnvVar             = "SERVICES_STUN_SERVERS"
	TURNServerEndpointEnvVar      = "SERVICES_TURN_SERVER_ENDPOINT"
	TURNServerPublicIPEnvVar      = "SERVICES_TURN_SERVER_PUBLIC_IP"
	TURNServerListenAddressEnvVar = "SERVICES_TURN_SERVER_LISTEN_ADDRESS"
	TURNServerPortEnvVar          = "SERVICES_TURN_SERVER_PORT"
	TURNServerRealmEnvVar         = "SERVICES_TURN_SERVER_REALM"
	STUNPortRangeEnvVar           = "SERVICES_STUN_PORT_RANGE"
	ExclusiveTURNServerEnvVar     = "SERVICES_EXCLUSIVE_TURN_SERVER"

	// MeshDNS
	MeshDNSListenUDPEnvVar      = "SERVICES_MESH_DNS_LISTEN_UDP"
	MeshDNSListenTCPEnvVar      = "SERVICES_MESH_DNS_LISTEN_TCP"
	MeshDNSTSIGKeyEnvVar        = "SERVICES_MESH_DNS_TSIG_KEY"
	MeshDNSReusePortEnvVar      = "SERVICES_MESH_DNS_REUSE_PORT"
	MeshDNSCompressionEnvVar    = "SERVICES_MESH_DNS_COMPRESSION"
	MeshDNSDomainEnvVar         = "SERVICES_MESH_DNS_DOMAIN"
	MeshDNSRequestTimeoutEnvVar = "SERVICES_MESH_DNS_REQUEST_TIMEOUT"
)

// Options contains the configuration for the gRPC server.
type Options struct {
	// GRPCListenAddress is the address to listen on.
	GRPCListenAddress string `json:"grpc-listen-address" yaml:"grpc-listen-address" toml:"grpc-listen-address"`
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
	// EnableLeaderProxy enables the leader proxy.
	EnableLeaderProxy bool `json:"enable-leader-proxy" yaml:"enable-leader-proxy" toml:"enable-leader-proxy"`
	// EnableMeshAPI enables the mesh API.
	EnableMeshAPI bool `json:"enable-mesh-api" yaml:"enable-mesh-api" toml:"enable-mesh-api"`
	// EnablePeerDiscoveryAPI enables the peer discovery API.
	EnablePeerDiscoveryAPI bool `json:"enable-peer-discovery-api" yaml:"enable-peer-discovery-api" toml:"enable-peer-discovery-api"`
	// EnableWebRTCAPI enables the WebRTC API.
	EnableWebRTCAPI bool `json:"enable-webrtc-api" yaml:"enable-webrtc-api" toml:"enable-webrtc-api"`
	// EnableMeshDNS enables the mesh DNS server.
	EnableMeshDNS bool `json:"enable-mesh-dns" yaml:"enable-mesh-dns" toml:"enable-mesh-dns"`
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
	// MeshDNSListenUDP is the address to listen on for UDP DNS requests.
	MeshDNSListenUDP string `json:"mesh-dns-listen-udp" yaml:"mesh-dns-listen-udp" toml:"mesh-dns-listen-udp"`
	// MeshDNSListenTCP is the address to listen on for TCP DNS requests.
	MeshDNSListenTCP string `json:"mesh-dns-listen-tcp" yaml:"mesh-dns-listen-tcp" toml:"mesh-dns-listen-tcp"`
	// MeshDNSTSIGKey is the TSIG key to use for DNS updates.
	MeshDNSTSIGKey string `json:"mesh-dns-tsig-key" yaml:"mesh-dns-tsig-key" toml:"mesh-dns-tsig-key"`
	// MeshDNSReusePort sets the number of listeners to start on each port.
	// This is only supported on Linux.
	MeshDNSReusePort int `json:"mesh-dns-reuse-port" yaml:"mesh-dns-reuse-port" toml:"mesh-dns-reuse-port"`
	// MeshDNSCompression is true if DNS compression should be enabled.
	MeshDNSCompression bool `json:"mesh-dns-compression" yaml:"mesh-dns-compression" toml:"mesh-dns-compression"`
	// MeshDNSDomain is the domain to use for the mesh DNS server.
	MeshDNSDomain string `json:"mesh-dns-domain" yaml:"mesh-dns-domain" toml:"mesh-dns-domain"`
	// MeshDNSRequestTimeout is the timeout for DNS requests.
	MeshDNSRequestTimeout time.Duration `json:"mesh-dns-request-timeout" yaml:"mesh-dns-request-timeout" toml:"mesh-dns-request-timeout"`
}

// NewOptions returns new Options with sensible defaults.
func NewOptions() *Options {
	return &Options{
		GRPCListenAddress:       ":8443",
		MetricsListenAddress:    ":8080",
		MetricsPath:             "/metrics",
		STUNServers:             "stun:stun.l.google.com:19302",
		TURNServerListenAddress: "0.0.0.0",
		TURNServerPort:          3478,
		TURNServerRealm:         "webmesh.io",
		STUNPortRange:           "49152-65535",
		MeshDNSListenUDP:        ":5353",
		MeshDNSListenTCP:        ":5353",
		MeshDNSDomain:           "webmesh.internal.",
		MeshDNSRequestTimeout:   5 * time.Second,
		MeshDNSCompression:      true,
	}
}

// BindFlags binds the gRPC options to the given flag set.
func (o *Options) BindFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.GRPCListenAddress, "services.grpc-listen-address", util.GetEnvDefault(ListenAddressEnvVar, ":8443"),
		"gRPC server listen address.")
	fs.StringVar(&o.TLSCertFile, "services.tls-cert-file", util.GetEnvDefault(CertFileEnvVar, ""),
		"gRPC server TLS certificate file.")
	fs.StringVar(&o.TLSKeyFile, "services.tls-key-file", util.GetEnvDefault(KeyFileEnvVar, ""),
		"gRPC server TLS key file.")
	fs.StringVar(&o.TLSCAFile, "services.tls-ca-file", util.GetEnvDefault(CAFileEnvVar, ""),
		"gRPC server TLS CA file.")
	fs.StringVar(&o.TLSClientCAFile, "services.tls-client-ca-file", util.GetEnvDefault(ClientCAFileEnvVar, ""),
		"gRPC server TLS client CA file.")
	fs.BoolVar(&o.MTLS, "services.mtls", util.GetEnvDefault(MTLSEnvVar, "false") == "true",
		"Enable mutual TLS.")
	fs.BoolVar(&o.SkipVerifyHostname, "services.skip-verify-hostname", util.GetEnvDefault(SkipVerifyHostnameEnvVar, "false") == "true",
		"Skip hostname verification.")
	fs.BoolVar(&o.Insecure, "services.insecure", util.GetEnvDefault(InsecureEnvVar, "false") == "true",
		"Don't use TLS for the gRPC server.")
	fs.BoolVar(&o.EnableMetrics, "services.enable-metrics", util.GetEnvDefault(EnableMetricsEnvVar, "false") == "true",
		"Enable gRPC metrics.")
	fs.StringVar(&o.MetricsListenAddress, "services.metrics-listen-address", util.GetEnvDefault(MetricsListenAddressEnvVar, ":8080"),
		"gRPC metrics listen address.")
	fs.StringVar(&o.MetricsPath, "services.metrics-path", util.GetEnvDefault(MetricsPathEnvVar, "/metrics"),
		"gRPC metrics path.")
	fs.BoolVar(&o.EnableLeaderProxy, "services.enable-leader-proxy", util.GetEnvDefault(EnableLeaderProxyEnvVar, "false") == "true",
		"Enable the leader proxy.")
	fs.BoolVar(&o.EnableMeshAPI, "services.enable-mesh-api", util.GetEnvDefault(EnableMeshAPIEnvVar, "false") == "true",
		"Enable the mesh API.")
	fs.BoolVar(&o.EnablePeerDiscoveryAPI, "services.enable-peer-discovery-api", util.GetEnvDefault(EnablePeerDiscoveryAPIEnvVar, "false") == "true",
		"Enable the peer discovery API.")
	fs.BoolVar(&o.EnableWebRTCAPI, "services.enable-webrtc-api", util.GetEnvDefault(EnableWebRTCAPIEnvVar, "false") == "true",
		"Enable the WebRTC API.")
	fs.BoolVar(&o.EnableMeshDNS, "services.enable-mesh-dns", util.GetEnvDefault(EnableMeshDNSEnvVar, "false") == "true",
		"Enable the mesh DNS server.")
	fs.StringVar(&o.STUNServers, "services.stun-servers", util.GetEnvDefault(STUNServersEnvVar, "stun:stun.l.google.com:19302"),
		"STUN servers to use.")
	fs.BoolVar(&o.EnableTURNServer, "services.enable-turn-server", util.GetEnvDefault(EnableTURNServerEnvVar, "false") == "true",
		"Enable the TURN server.")
	fs.StringVar(&o.TURNServerEndpoint, "services.turn-server-endpoint", util.GetEnvDefault(TURNServerEndpointEnvVar, ""),
		"The TURN server endpoint. If empty, the public IP will be used.")
	fs.StringVar(&o.TURNServerPublicIP, "services.turn-server-public-ip", util.GetEnvDefault(TURNServerPublicIPEnvVar, ""),
		"The address advertised for STUN requests.")
	fs.StringVar(&o.TURNServerListenAddress, "services.turn-server-listen-address", util.GetEnvDefault(TURNServerListenAddressEnvVar, "0.0.0.0"),
		"Address to listen on for TURN connections.")
	fs.IntVar(&o.TURNServerPort, "services.turn-server-port", util.GetEnvIntDefault(TURNServerPortEnvVar, 3478),
		"Port to listen on for TURN connections.")
	fs.StringVar(&o.TURNServerRealm, "services.turn-server-realm", util.GetEnvDefault(TURNServerRealmEnvVar, "webmesh.io"),
		"Realm used for TURN server authentication.")
	fs.StringVar(&o.STUNPortRange, "services.stun-port-range", util.GetEnvDefault(STUNPortRangeEnvVar, "49152-65535"),
		"Port range to use for STUN.")
	fs.BoolVar(&o.ExclusiveTURNServer, "services.exclusive-turn-server", util.GetEnvDefault(ExclusiveTURNServerEnvVar, "false") == "true",
		`Replace all stun-servers with the local TURN server. 
The equivalent of stun-servers=stun:<turn-server-public-ip>:<turn-server-port>.`)
	fs.StringVar(&o.MeshDNSListenUDP, "services.mesh-dns-listen-udp", util.GetEnvDefault(MeshDNSListenUDPEnvVar, ":5353"),
		"UDP address to listen on for DNS requests.")
	fs.StringVar(&o.MeshDNSListenTCP, "services.mesh-dns-listen-tcp", util.GetEnvDefault(MeshDNSListenTCPEnvVar, ":5353"),
		"TCP address to listen on for DNS requests.")
	fs.StringVar(&o.MeshDNSDomain, "services.mesh-dns-domain", util.GetEnvDefault(MeshDNSDomainEnvVar, "webmesh.internal"),
		"Domain to use for mesh DNS.")
	fs.StringVar(&o.MeshDNSTSIGKey, "services.mesh-dns-tsig-key", util.GetEnvDefault(MeshDNSTSIGKeyEnvVar, ""),
		"TSIG key to use for mesh DNS.")
	fs.IntVar(&o.MeshDNSReusePort, "services.mesh-dns-reuse-port", util.GetEnvIntDefault(MeshDNSReusePortEnvVar, 0),
		"Enable SO_REUSEPORT for mesh DNS.")
	fs.BoolVar(&o.MeshDNSCompression, "services.mesh-dns-compression", util.GetEnvDefault(MeshDNSCompressionEnvVar, "true") == "true",
		"Enable DNS compression for mesh DNS.")
	fs.DurationVar(&o.MeshDNSRequestTimeout, "services.mesh-dns-request-timeout", util.GetEnvDurationDefault(MeshDNSRequestTimeoutEnvVar, 5*time.Second),
		"Timeout for mesh DNS requests.")
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
	if o.EnableMeshDNS {
		if o.MeshDNSListenTCP == "" && o.MeshDNSListenUDP == "" {
			return errors.New("must specify a TCP or UDP address for mesh DNS")
		}
		if o.MeshDNSDomain == "" {
			return errors.New("must specify a domain for mesh DNS")
		}
	}
	return nil
}

// ListenPort returns the port the options are configured to listen on.
func (o *Options) ListenPort() (int, error) {
	_, port, err := net.SplitHostPort(o.GRPCListenAddress)
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
	if o.EnableLeaderProxy {
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

// ToFeatureSet converts the options to a feature set.
func (o *Options) ToFeatureSet() []v1.Feature {
	features := []v1.Feature{v1.Feature_NODES}
	if o.EnableLeaderProxy {
		features = append(features, v1.Feature_LEADER_PROXY)
	}
	if o.EnableMeshAPI {
		features = append(features, v1.Feature_MESH_API)
	}
	if o.EnablePeerDiscoveryAPI {
		features = append(features, v1.Feature_PEER_DISCOVERY)
	}
	if o.EnableMetrics {
		features = append(features, v1.Feature_METRICS)
	}
	if o.EnableWebRTCAPI {
		features = append(features, v1.Feature_ICE_NEGOTIATION)
	}
	if o.EnableTURNServer {
		features = append(features, v1.Feature_TURN_SERVER)
	}
	if o.EnableMeshDNS {
		features = append(features, v1.Feature_MESH_DNS)
	}
	return features
}
