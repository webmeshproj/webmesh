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

package config

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/spf13/pflag"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/webmeshproj/webmesh/pkg/context"
	rbacdb "github.com/webmeshproj/webmesh/pkg/meshdb/rbac"
	"github.com/webmeshproj/webmesh/pkg/meshnode"
	netutil "github.com/webmeshproj/webmesh/pkg/net/util"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/services/leaderproxy"
	"github.com/webmeshproj/webmesh/pkg/services/membership"
	"github.com/webmeshproj/webmesh/pkg/services/meshapi"
	"github.com/webmeshproj/webmesh/pkg/services/meshdns"
	"github.com/webmeshproj/webmesh/pkg/services/metrics"
	"github.com/webmeshproj/webmesh/pkg/services/node"
	"github.com/webmeshproj/webmesh/pkg/services/rbac"
	"github.com/webmeshproj/webmesh/pkg/services/storage"
	"github.com/webmeshproj/webmesh/pkg/services/turn"
	"github.com/webmeshproj/webmesh/pkg/services/webrtc"
)

// ServiceOptions contains the configuration for the mesh services.
type ServiceOptions struct {
	// API options
	API APIOptions `koanf:"api,omitempty"`
	// WebRTC options
	WebRTC WebRTCOptions `koanf:"webrtc,omitempty"`
	// MeshDNS options
	MeshDNS MeshDNSOptions `koanf:"meshdns,omitempty"`
	// TURN options
	TURN TURNOptions `koanf:"turn,omitempty"`
	// Metrics options
	Metrics MetricsOptions `koanf:"metrics,omitempty"`
}

// NewServiceOptions returns a new ServiceOptions with the default values.
func NewServiceOptions() ServiceOptions {
	return ServiceOptions{
		API:     NewAPIOptions(),
		WebRTC:  NewWebRTCOptions(),
		MeshDNS: NewMeshDNSOptions(),
		TURN:    NewTURNOptions(),
		Metrics: NewMetricsOptions(),
	}
}

// BindFlags binds the flags.
func (s *ServiceOptions) BindFlags(prefix string, fl *pflag.FlagSet) {
	s.API.BindFlags(prefix, fl)
	s.WebRTC.BindFlags(prefix, fl)
	s.TURN.BindFlags(prefix, fl)
	s.Metrics.BindFlags(prefix, fl)
	// Don't recurse on meshdns flags in bridge configurations
	if prefix == "" {
		s.MeshDNS.BindFlags(prefix, fl)
	}
}

// Validate validates the options.
func (s *ServiceOptions) Validate() error {
	err := s.API.Validate()
	if err != nil {
		return err
	}
	if s.TURN.Enabled {
		err := s.TURN.Validate()
		if err != nil {
			return err
		}
	}
	if s.Metrics.Enabled {
		err := s.Metrics.Validate()
		if err != nil {
			return err
		}
	}
	if s.WebRTC.Enabled {
		err := s.WebRTC.Validate()
		if err != nil {
			return err
		}
	}
	return nil
}

// APIOptions are the options for which APIs to register and expose.
type APIOptions struct {
	// Disabled is true if the gRPC API should be disabled.
	// The node will still be able to join a mesh, but will not be able to
	// serve any APIs or provide proxying services.
	Disabled bool `koanf:"disabled,omitempty"`
	// ListenAddress is the gRPC address to listen on.
	ListenAddress string `koanf:"listen-address,omitempty"`
	// WebEnabled enables serving gRPC over HTTP/1.1.
	WebEnabled bool `koanf:"web-enabled,omitempty"`
	// TLSCertFile is the path to the TLS certificate file.
	TLSCertFile string `koanf:"tls-cert-file,omitempty"`
	// TLSCertData is the TLS certificate data.
	TLSCertData string `koanf:"tls-cert-data,omitempty"`
	// TLSKeyFile is the path to the TLS key file.
	TLSKeyFile string `koanf:"tls-key-file,omitempty"`
	// TLSKeyData is the TLS key data.
	TLSKeyData string `koanf:"tls-key-data,omitempty"`
	// Insecure is true if the transport is insecure.
	Insecure bool `koanf:"insecure,omitempty"`
	// DisableLeaderProxy is true if the leader proxy should be disabled.
	DisableLeaderProxy bool `koanf:"disable-leader-proxy,omitempty"`
	// MeshEnabled is true if the mesh API should be registered.
	MeshEnabled bool `koanf:"mesh-enabled,omitempty"`
	// AdminEnabled is true if the admin API should be registered.
	AdminEnabled bool `koanf:"admin-enabled,omitempty"`
}

// NewAPIOptions returns a new APIOptions with the default values.
func NewAPIOptions() APIOptions {
	return APIOptions{
		ListenAddress: services.DefaultGRPCListenAddress,
	}
}

// BindFlags binds the flags.
func (a *APIOptions) BindFlags(prefix string, fl *pflag.FlagSet) {
	fl.BoolVar(&a.Disabled, prefix+"services.api.disabled", false, "Disable the API. This is ignored when joining as a Raft member.")
	fl.StringVar(&a.ListenAddress, prefix+"services.api.listen-address", services.DefaultGRPCListenAddress, "gRPC listen address.")
	fl.BoolVar(&a.WebEnabled, prefix+"services.api.web-enabled", false, "Enable gRPC over HTTP/1.1.")
	fl.BoolVar(&a.DisableLeaderProxy, prefix+"services.api.disable-leader-proxy", false, "Disable the leader proxy.")
	fl.StringVar(&a.TLSCertFile, prefix+"services.api.tls-cert-file", "", "TLS certificate file.")
	fl.StringVar(&a.TLSCertData, prefix+"services.api.tls-cert-data", "", "TLS certificate data.")
	fl.StringVar(&a.TLSKeyFile, prefix+"services.api.tls-key-file", "", "TLS key file.")
	fl.StringVar(&a.TLSKeyData, prefix+"services.api.tls-key-data", "", "TLS key data.")
	fl.BoolVar(&a.Insecure, prefix+"services.api.insecure", false, "Disable TLS.")
	fl.BoolVar(&a.MeshEnabled, prefix+"services.api.mesh-enabled", false, "Enable and register the MeshAPI.")
	fl.BoolVar(&a.AdminEnabled, prefix+"services.api.admin-enabled", false, "Enable and register the AdminAPI.")
}

// Validate validates the options.
func (a *APIOptions) Validate() error {
	if a.Disabled {
		return nil
	}
	if a.ListenAddress == "" {
		return fmt.Errorf("services.api.listen-address must be set")
	}
	_, _, err := net.SplitHostPort(a.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen-address is invalid: %w", err)
	}
	if !a.Insecure {
		if (a.TLSCertFile == "" || a.TLSKeyFile == "") || (a.TLSCertData == "" || a.TLSKeyData == "") {
			return fmt.Errorf("tls-cert-file and tls-key-file or tls-cert-data and tls-key-data must be set")
		}
	}
	return nil
}

// WebRTCOptions are the options for the WebRTC API.
type WebRTCOptions struct {
	// Enabled enables the WebRTC API.
	Enabled bool `koanf:"enabled,omitempty"`
	// STUNServers is a list of STUN servers to use for the WebRTC API.
	STUNServers []string `koanf:"stun-servers,omitempty"`
}

// NewWebRTCOptions returns a new WebRTCOptions with the default values.
func NewWebRTCOptions() WebRTCOptions {
	return WebRTCOptions{
		Enabled:     false,
		STUNServers: webrtc.DefaultSTUNServers,
	}
}

// BindFlags binds the flags.
func (w *WebRTCOptions) BindFlags(prefix string, fl *pflag.FlagSet) {
	fl.BoolVar(&w.Enabled, prefix+"services.webrtc.enabled", false, "Enable and register the WebRTC API.")
	fl.StringSliceVar(&w.STUNServers, prefix+"services.webrtc.stun-servers", webrtc.DefaultSTUNServers, "TURN/STUN servers to use for the WebRTC API.")
}

// Validate validates the options.
func (w *WebRTCOptions) Validate() error {
	return nil
}

// TURNOptions are the options for the TURN server.
type TURNOptions struct {
	// Enabled enables the TURN server.
	Enabled bool `koanf:"enabled,omitempty"`
	// Endpoint is the endpoint to advertise for the TURN server. If empty, the public IP and listen port is used.
	Endpoint string `koanf:"endpoint,omitempty"`
	// PublicIP is the address advertised for STUN/TURN requests.
	PublicIP string `koanf:"public-ip,omitempty"`
	// ListenAddress is the address to listen on for STUN/TURN connections.
	ListenAddress string `koanf:"listen-address,omitempty"`
	// Realm is the realm used for TURN server authentication.
	Realm string `koanf:"realm,omitempty"`
	// TURNPortRange is the port range to use for allocating TURN relays.
	TURNPortRange string `koanf:"port-range,omitempty"`
}

// NewTURNOptions returns a new TURNOptions with the default values.
func NewTURNOptions() TURNOptions {
	return TURNOptions{
		Enabled:       false,
		Endpoint:      "",
		PublicIP:      "",
		ListenAddress: turn.DefaultListenAddress,
		Realm:         "webmesh",
		TURNPortRange: turn.DefaultPortRange,
	}
}

// BindFlags binds the flags.
func (t *TURNOptions) BindFlags(prefix string, fl *pflag.FlagSet) {
	fl.BoolVar(&t.Enabled, prefix+"services.turn.enabled", false, "Enable TURN server.")
	fl.StringVar(&t.Endpoint, prefix+"services.turn.endpoint", "", "TURN endpoint to advertise.")
	fl.StringVar(&t.PublicIP, prefix+"services.turn.public-ip", "", "Public IP to advertise for STUN/TURN requests.")
	fl.StringVar(&t.ListenAddress, prefix+"services.turn.listen-address", turn.DefaultListenAddress, "Address to listen on for STUN/TURN requests.")
	fl.StringVar(&t.Realm, prefix+"services.turn.realm", "webmesh", "Realm used for TURN server authentication.")
	fl.StringVar(&t.TURNPortRange, prefix+"services.turn.port-range", turn.DefaultPortRange, "Port range to use for TURN relays.")
}

// Validate values the TURN options.
func (t *TURNOptions) Validate() error {
	if !t.Enabled {
		return nil
	}
	if t.ListenAddress == "" {
		return fmt.Errorf("services.turn.listen-address must be set")
	} else {
		_, _, err := net.SplitHostPort(t.ListenAddress)
		if err != nil {
			return fmt.Errorf("services.turn.listen-address is invalid: %w", err)
		}
	}
	if t.PublicIP == "" || t.Endpoint == "" {
		return fmt.Errorf("services.turn.public-ip or services.turn.endpoint must be set")
	}
	if t.PublicIP != "" {
		_, err := netip.ParseAddr(t.PublicIP)
		if err != nil {
			return fmt.Errorf("services.turn.public-ip is invalid: %w", err)
		}
	}
	_, _, err := netutil.ParsePortRange(t.TURNPortRange)
	if err != nil {
		return fmt.Errorf("services.turn.port-range is invalid: %w", err)
	}
	return nil
}

// ListenPort returns the listen port for this TURN configuration. or 0
// if not enabled or invalid.
func (t *TURNOptions) ListenPort() uint16 {
	if !t.Enabled {
		return 0
	}
	_, port, err := net.SplitHostPort(t.ListenAddress)
	if err != nil {
		return 0
	}
	out, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return uint16(out)
}

// BindFlags binds the flags.
type MeshDNSOptions struct {
	// Enabled enables mesh DNS.
	Enabled bool `koanf:"enabled,omitempty"`
	// ListenUDP is the UDP address to listen on.
	ListenUDP string `koanf:"listen-udp,omitempty"`
	// ListenTCP is the address to listen on for TCP DNS requests.
	ListenTCP string `koanf:"listen-tcp,omitempty"`
	// ReusePort sets the number of listeners to start on each port.
	// This is only supported on Linux.
	ReusePort int `koanf:"reuse-port,omitempty"`
	// EnableCompression is true if DNS compression should be enabled.
	EnableCompression bool `koanf:"compression,omitempty"`
	// RequestTimeout is the timeout for DNS requests.
	RequestTimeout time.Duration `koanf:"request-timeout,omitempty"`
	// Forwarders are the DNS forwarders to use. If empty, the system DNS servers will be used.
	Forwarders []string `koanf:"forwarders,omitempty"`
	// SubscribeForwarders will subscribe to new nodes that are able to forward requests for other meshes.
	// These forwarders will be placed at the bottom of the forwarders list.
	SubscribeForwarders bool `koanf:"subscribe-forwarders,omitempty"`
	// DisableForwarding disables forwarding requests entirely.
	DisableForwarding bool `koanf:"disable-forwarding,omitempty"`
	// CacheSize is the size of the remote DNS cache.
	CacheSize int `koanf:"cache-size,omitempty"`
	// IPv6Only will only respond to IPv6 requests.
	IPv6Only bool `koanf:"ipv6-only,omitempty"`
}

// NewMeshDNSOptions returns a new MeshDNSOptions with the default values.
func NewMeshDNSOptions() MeshDNSOptions {
	return MeshDNSOptions{
		Enabled:             false,
		ListenUDP:           meshdns.DefaultListenUDP,
		ListenTCP:           meshdns.DefaultListenTCP,
		ReusePort:           0,
		EnableCompression:   true,
		RequestTimeout:      time.Second * 5,
		Forwarders:          nil,
		SubscribeForwarders: false,
		DisableForwarding:   false,
		CacheSize:           100,
		IPv6Only:            false,
	}
}

// BindFlags binds the flags.
func (m *MeshDNSOptions) BindFlags(prefix string, fl *pflag.FlagSet) {
	fl.BoolVar(&m.Enabled, prefix+"services.meshdns.enabled", false, "Enable mesh DNS.")
	fl.StringVar(&m.ListenUDP, prefix+"services.meshdns.listen-udp", meshdns.DefaultListenUDP, "UDP address to listen on for DNS requests.")
	fl.StringVar(&m.ListenTCP, prefix+"services.meshdns.listen-tcp", meshdns.DefaultListenTCP, "TCP address to listen on for DNS requests.")
	fl.IntVar(&m.ReusePort, prefix+"services.meshdns.reuse-port", 0, "Enable SO_REUSEPORT for mesh DNS. Only available on Linux systems.")
	fl.BoolVar(&m.EnableCompression, prefix+"services.meshdns.compression", true, "Enable DNS compression.")
	fl.DurationVar(&m.RequestTimeout, prefix+"services.meshdns.request-timeout", time.Second*5, "DNS request timeout.")
	fl.StringSliceVar(&m.Forwarders, prefix+"services.meshdns.forwarders", nil, "DNS forwarders (default = system resolvers).")
	fl.BoolVar(&m.SubscribeForwarders, prefix+"services.meshdns.subscribe-forwarders", false, "Subscribe to new nodes that can forward requests.")
	fl.BoolVar(&m.DisableForwarding, prefix+"services.meshdns.disable-forwarding", false, "Disable forwarding requests.")
	fl.IntVar(&m.CacheSize, prefix+"services.meshdns.cache-size", 100, "Size of the remote DNS cache (0 = disabled).")
	fl.BoolVar(&m.IPv6Only, prefix+"services.meshdns.ipv6-only", false, "Only respond to IPv6 requests.")
}

// ListenPort returns the listen port for the MeshDNS server is enabled.
func (m *MeshDNSOptions) ListenPort() uint16 {
	if !m.Enabled {
		return 0
	}
	_, port, err := net.SplitHostPort(m.ListenUDP)
	if err != nil {
		return 0
	}
	out, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return uint16(out)
}

// Metrics are options for exposing metrics.
type MetricsOptions struct {
	// Enabled is true if metrics should be enabled.
	Enabled bool `koanf:"enabled,omitempty"`
	// MetricsListenAddress is the address to listen on for metrics.
	ListenAddress string `koanf:"listen-address,omitempty"`
	// MetricsPath is the path to serve metrics on.
	Path string `koanf:"path,omitempty"`
}

// NewMetricsOptions returns a new MetricsOptions with the default values.
func NewMetricsOptions() MetricsOptions {
	return MetricsOptions{
		Enabled:       false,
		ListenAddress: metrics.DefaultListenAddress,
		Path:          metrics.DefaultPath,
	}
}

// BindFlags binds the flags.
func (m *MetricsOptions) BindFlags(prefix string, fl *pflag.FlagSet) {
	fl.BoolVar(&m.Enabled, prefix+"services.metrics.enabled", false, "Enable gRPC metrics.")
	fl.StringVar(&m.ListenAddress, prefix+"services.metrics.listen-address", metrics.DefaultListenAddress, "gRPC metrics listen address.")
	fl.StringVar(&m.Path, prefix+"services.metrics.path", metrics.DefaultPath, "gRPC metrics path.")
}

// ListenPort returns the listen port for the Metrics server is enabled.
func (m *MetricsOptions) ListenPort() uint16 {
	if !m.Enabled {
		return 0
	}
	_, port, err := net.SplitHostPort(m.ListenAddress)
	if err != nil {
		return 0
	}
	out, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return uint16(out)
}

// Validate validates the options.
func (m *MetricsOptions) Validate() error {
	if !m.Enabled {
		return nil
	}
	if m.ListenAddress == "" {
		return fmt.Errorf("services.metrics.listen-address must be set")
	}
	_, _, err := net.SplitHostPort(m.ListenAddress)
	if err != nil {
		return fmt.Errorf("services.metrics.listen-address is invalid: %w", err)
	}
	return nil
}

// RegisterAPIs registers the configured APIs to the given server.
func (o *Config) RegisterAPIs(ctx context.Context, conn meshnode.Node, srv *services.Server) error {
	log := context.LoggerFrom(ctx)
	var rbacDisabled bool
	var err error
	maxTries := 5
	for i := 0; i < maxTries; i++ {
		rbacDisabled, err = rbacdb.New(conn.Storage()).IsDisabled(context.Background())
		if err != nil {
			log.Error("Failed to check rbac status", "error", err.Error())
			if i == maxTries-1 {
				return err
			}
			time.Sleep(1 * time.Second)
			continue
		}
		break
	}
	var rbacEvaluator rbac.Evaluator
	insecureServices := !conn.Plugins().HasAuth() || rbacDisabled
	if insecureServices {
		log.Warn("Running services without authorization")
		rbacEvaluator = rbac.NewNoopEvaluator()
	} else {
		rbacEvaluator = rbac.NewStoreEvaluator(conn.Storage())
	}
	// Always register the node API
	log.Debug("Registering node service")
	v1.RegisterNodeServer(srv, node.NewServer(ctx, node.Options{
		Raft:       conn.Raft(),
		WireGuard:  conn.Network().WireGuard(),
		NodeDialer: conn,
		Plugins:    conn.Plugins(),
		Features:   o.NewFeatureSet(),
	}))
	// Register membership and storage if we are a raft member
	if o.IsRaftMember() {
		log.Debug("Registering membership service")
		v1.RegisterMembershipServer(srv, membership.NewServer(ctx, membership.Options{
			Raft:      conn.Raft(),
			Plugins:   conn.Plugins(),
			RBAC:      rbacEvaluator,
			WireGuard: conn.Network().WireGuard(),
		}))
		log.Debug("Registering storage service")
		v1.RegisterStorageServer(srv, storage.NewServer(ctx, conn.Raft(), rbacEvaluator, conn.Network().WireGuard()))
	}
	// Register any other enabled APIs
	if o.Services.API.MeshEnabled {
		log.Debug("Registering mesh api")
		v1.RegisterMeshServer(srv, meshapi.NewServer(conn.Storage(), conn.Raft()))
	}
	if o.Services.WebRTC.Enabled {
		log.Debug("Registering WebRTC api")
		// Check if we are a TURN server, and if so - register the TURN server
		if o.Services.TURN.Enabled {
			log.Debug("Registering local TURN server with WebRTC API")
			turnAddr := net.JoinHostPort(o.Services.TURN.PublicIP, strconv.Itoa(int(o.Services.TURN.ListenPort())))
			turnAddr = fmt.Sprintf("turn:%s", turnAddr)
			o.Services.WebRTC.STUNServers = append([]string{turnAddr}, o.Services.WebRTC.STUNServers...)
		}
		v1.RegisterWebRTCServer(srv, webrtc.NewServer(webrtc.Options{
			ID:          conn.ID(),
			Storage:     conn.Storage(),
			Wireguard:   conn.Network().WireGuard(),
			NodeDialer:  conn,
			RBAC:        rbacEvaluator,
			STUNServers: o.Services.WebRTC.STUNServers,
		}))
	}
	return nil
}

// NewFeatureSet returns a new FeatureSet for the given node options.
func (o *Config) NewFeatureSet() []*v1.FeaturePort {
	if o.Mesh.DisableFeatureAdvertisement {
		return []*v1.FeaturePort{}
	}
	// We always expose the node API
	var features []*v1.FeaturePort
	if !o.Services.API.Disabled {
		features = append(features, &v1.FeaturePort{
			Feature: v1.Feature_NODES,
			Port:    int32(o.Mesh.GRPCAdvertisePort),
		})
	}
	// If we are a raft member, we automatically serve storage and membership
	if o.IsRaftMember() {
		features = append(features, &v1.FeaturePort{
			Feature: v1.Feature_STORAGE,
			Port:    int32(o.Mesh.GRPCAdvertisePort),
		})
		features = append(features, &v1.FeaturePort{
			Feature: v1.Feature_MEMBERSHIP,
			Port:    int32(o.Mesh.GRPCAdvertisePort),
		})
		features = append(features, &v1.FeaturePort{
			Feature: v1.Feature_RAFT,
			Port:    int32(o.RaftListenPort()),
		})
	}
	if !o.Services.API.Disabled {
		if !o.Services.API.DisableLeaderProxy {
			features = append(features, &v1.FeaturePort{
				Feature: v1.Feature_LEADER_PROXY,
				Port:    int32(o.Mesh.GRPCAdvertisePort),
			})
		}
		if o.Services.API.MeshEnabled {
			features = append(features, &v1.FeaturePort{
				Feature: v1.Feature_MESH_API,
				Port:    int32(o.Mesh.GRPCAdvertisePort),
			})
		}
		if o.Services.API.AdminEnabled {
			features = append(features, &v1.FeaturePort{
				Feature: v1.Feature_ADMIN_API,
				Port:    int32(o.Mesh.GRPCAdvertisePort),
			})
		}
		if o.Services.WebRTC.Enabled {
			features = append(features, &v1.FeaturePort{
				Feature: v1.Feature_ICE_NEGOTIATION,
				Port:    int32(o.Mesh.GRPCAdvertisePort),
			})
		}
	}
	if o.Services.TURN.Enabled {
		features = append(features, &v1.FeaturePort{
			Feature: v1.Feature_TURN_SERVER,
			Port:    int32(o.Services.TURN.ListenPort()),
		})
	}
	if o.Services.MeshDNS.Enabled {
		features = append(features, &v1.FeaturePort{
			Feature: v1.Feature_MESH_DNS,
			Port:    int32(o.Services.MeshDNS.ListenPort()),
		})
	}
	if o.Services.Metrics.Enabled {
		features = append(features, &v1.FeaturePort{
			Feature: v1.Feature_METRICS,
			Port:    int32(o.Services.Metrics.ListenPort()),
		})
	}
	return features
}

// NewServiceOptions returns new options for the webmesh services.
func (o *Config) NewServiceOptions(ctx context.Context, conn meshnode.Node) (conf services.Options, err error) {
	if !o.Services.API.Disabled {
		conf.ListenAddress = o.Services.API.ListenAddress
		// Build out the server options
		if !o.Services.API.Insecure {
			// Setup TLS
			tlsOpts, err := o.NewServerTLSOptions()
			if err != nil {
				return conf, err
			}
			conf.ServerOptions = append(conf.ServerOptions, tlsOpts)
		} else {
			// Append insecure options
			conf.ServerOptions = append(conf.ServerOptions, grpc.Creds(insecure.NewCredentials()))
		}
		// Always append logging middlewares to the server options
		unarymiddlewares := []grpc.UnaryServerInterceptor{
			context.LogInjectUnaryServerInterceptor(context.LoggerFrom(ctx)),
			logging.UnaryServerInterceptor(InterceptorLogger(), logging.WithLogOnEvents(logging.StartCall, logging.FinishCall)),
		}
		streammiddlewares := []grpc.StreamServerInterceptor{
			context.LogInjectStreamServerInterceptor(context.LoggerFrom(ctx)),
			logging.StreamServerInterceptor(InterceptorLogger(), logging.WithLogOnEvents(logging.StartCall, logging.FinishCall)),
		}

		// If metrics are enabled, register the metrics interceptor
		if o.Services.Metrics.Enabled {
			unarymiddlewares, streammiddlewares, err = metrics.AppendMetricsMiddlewares(context.LoggerFrom(ctx), unarymiddlewares, streammiddlewares)
			if err != nil {
				return conf, err
			}
		}

		// Register any authentication interceptors
		if conn.Plugins().HasAuth() {
			unarymiddlewares = append(unarymiddlewares, conn.Plugins().AuthUnaryInterceptor())
			streammiddlewares = append(streammiddlewares, conn.Plugins().AuthStreamInterceptor())
		}

		if !o.Services.API.DisableLeaderProxy {
			leaderProxy := leaderproxy.New(conn.Raft(), conn, conn.Network().WireGuard())
			unarymiddlewares = append(unarymiddlewares, leaderProxy.UnaryInterceptor())
			streammiddlewares = append(streammiddlewares, leaderProxy.StreamInterceptor())
		}

		conf.ServerOptions = append(conf.ServerOptions, grpc.ChainUnaryInterceptor(unarymiddlewares...))
		conf.ServerOptions = append(conf.ServerOptions, grpc.ChainStreamInterceptor(streammiddlewares...))
	} else {
		conf.DisableGRPC = true
	}
	// Append the enabled mesh services
	if o.Services.MeshDNS.Enabled {
		dnsServer := meshdns.NewServer(ctx, &meshdns.Options{
			UDPListenAddr:     o.Services.MeshDNS.ListenUDP,
			TCPListenAddr:     o.Services.MeshDNS.ListenTCP,
			ReusePort:         o.Services.MeshDNS.ReusePort,
			Compression:       o.Services.MeshDNS.EnableCompression,
			RequestTimeout:    o.Services.MeshDNS.RequestTimeout,
			Forwarders:        o.Services.MeshDNS.Forwarders,
			DisableForwarding: o.Services.MeshDNS.DisableForwarding,
			CacheSize:         o.Services.MeshDNS.CacheSize,
		})
		// Automatically register the local domain
		err := dnsServer.RegisterDomain(meshdns.DomainOptions{
			MeshDomain:          conn.Domain(),
			MeshStorage:         conn.Storage(),
			Raft:                conn.Raft(),
			IPv6Only:            o.Services.MeshDNS.IPv6Only,
			SubscribeForwarders: o.Services.MeshDNS.SubscribeForwarders,
		})
		if err != nil {
			return conf, err
		}
		conf.Servers = append(conf.Servers, dnsServer)
	}
	if o.Services.TURN.Enabled {
		turnServer := turn.NewServer(ctx, turn.Options{
			PublicIP:  o.Services.TURN.PublicIP,
			ListenUDP: o.Services.TURN.ListenAddress,
			Realm:     o.Services.TURN.Realm,
			PortRange: o.Services.TURN.TURNPortRange,
		})
		conf.Servers = append(conf.Servers, turnServer)
	}
	if o.Services.Metrics.Enabled {
		metricsServer := metrics.New(ctx, metrics.Options{
			ListenAddress: o.Services.Metrics.ListenAddress,
			Path:          o.Services.Metrics.Path,
		})
		conf.Servers = append(conf.Servers, metricsServer)
	}
	return
}

// NewServerTLSOptions returns new TLS options for the gRPC server.
func (o *Config) NewServerTLSOptions() (grpc.ServerOption, error) {
	tlsConfig := &tls.Config{}
	if o.Services.API.TLSCertFile != "" && o.Services.API.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(o.Services.API.TLSCertFile, o.Services.API.TLSKeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	if o.Services.API.TLSCertData != "" && o.Services.API.TLSKeyData != "" {
		certData, err := base64.StdEncoding.DecodeString(o.Services.API.TLSCertData)
		if err != nil {
			return nil, err
		}
		keyData, err := base64.StdEncoding.DecodeString(o.Services.API.TLSKeyData)
		if err != nil {
			return nil, err
		}
		cert, err := tls.X509KeyPair(certData, keyData)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	// If we are using mTLS we need to request a client certificate
	if o.Auth.MTLS != (MTLSOptions{}) {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return grpc.Creds(credentials.NewTLS(tlsConfig)), nil
}

// InterceptorLogger returns a logging.Logger that logs to the given slog.Logger.
func InterceptorLogger() logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		context.LoggerFrom(ctx).Log(ctx, slog.Level(lvl), msg, fields...)
	})
}
