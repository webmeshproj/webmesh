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
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/spf13/pflag"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/webmeshproj/webmesh/pkg/context"
	netutil "github.com/webmeshproj/webmesh/pkg/meshnet/util"
	"github.com/webmeshproj/webmesh/pkg/meshnode"
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
// Disabled sets the initial state of whether the gRPC API is enabled.
func NewServiceOptions(disabled bool) ServiceOptions {
	return ServiceOptions{
		API:     NewAPIOptions(disabled),
		WebRTC:  NewWebRTCOptions(),
		MeshDNS: NewMeshDNSOptions(),
		TURN:    NewTURNOptions(),
		Metrics: NewMetricsOptions(),
	}
}

// NewInsecureServiceOptions returns a new ServiceOptions with the default values
// and insecure set to true. Disabled sets the initial state of whether the gRPC API
// is enabled.
func NewInsecureServiceOptions(disabled bool) ServiceOptions {
	return ServiceOptions{
		API:     NewInsecureAPIOptions(disabled),
		WebRTC:  NewWebRTCOptions(),
		MeshDNS: NewMeshDNSOptions(),
		TURN:    NewTURNOptions(),
		Metrics: NewMetricsOptions(),
	}
}

// BindFlags binds the flags.
func (s *ServiceOptions) BindFlags(prefix string, fl *pflag.FlagSet) {
	s.API.BindFlags(prefix+"api.", fl)
	s.WebRTC.BindFlags(prefix+"webrtc.", fl)
	s.TURN.BindFlags(prefix+"turn.", fl)
	s.Metrics.BindFlags(prefix+"metrics.", fl)
	// Don't recurse on meshdns flags in bridge configurations
	if !strings.Contains(prefix, "bridge.") {
		s.MeshDNS.BindFlags(prefix+"meshdns.", fl)
	}
}

// Validate validates the options.
func (s *ServiceOptions) Validate() error {
	if s == nil {
		return nil
	}
	err := s.API.Validate()
	if err != nil {
		return err
	}
	err = s.TURN.Validate()
	if err != nil {
		return err
	}
	err = s.MeshDNS.Validate()
	if err != nil {
		return err
	}
	err = s.Metrics.Validate()
	if err != nil {
		return err
	}
	err = s.WebRTC.Validate()
	if err != nil {
		return err
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
	// MTLS is true if mutual TLS should be enabled.
	MTLS bool `koanf:"mtls,omitempty"`
	// MTLSClientCAFile is the path to the client CA file. This is not usually
	// required and handled by the mtls auth plugin.
	MTLSClientCAFile string `koanf:"mtls-client-ca-file,omitempty"`
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
func NewAPIOptions(disabled bool) APIOptions {
	return APIOptions{
		Disabled:      disabled,
		ListenAddress: services.DefaultGRPCListenAddress,
	}
}

// NewInsecureAPIOptions returns a new APIOptions with the default values
// and insecure set to true.
func NewInsecureAPIOptions(disabled bool) APIOptions {
	return APIOptions{
		Disabled:      disabled,
		ListenAddress: services.DefaultGRPCListenAddress,
		Insecure:      true,
	}
}

// BindFlags binds the flags.
func (a *APIOptions) BindFlags(prefix string, fl *pflag.FlagSet) {
	fl.BoolVar(&a.Disabled, prefix+"disabled", a.Disabled, "Disable the API. This is ignored when joining as a Raft member.")
	fl.StringVar(&a.ListenAddress, prefix+"listen-address", a.ListenAddress, "gRPC listen address.")
	fl.BoolVar(&a.WebEnabled, prefix+"web-enabled", a.WebEnabled, "Enable gRPC over HTTP/1.1.")
	fl.BoolVar(&a.DisableLeaderProxy, prefix+"disable-leader-proxy", a.DisableLeaderProxy, "Disable the leader proxy.")
	fl.StringVar(&a.TLSCertFile, prefix+"tls-cert-file", a.TLSCertFile, "TLS certificate file.")
	fl.StringVar(&a.TLSCertData, prefix+"tls-cert-data", a.TLSCertData, "TLS certificate data.")
	fl.StringVar(&a.TLSKeyFile, prefix+"tls-key-file", a.TLSKeyFile, "TLS key file.")
	fl.StringVar(&a.TLSKeyData, prefix+"tls-key-data", a.TLSKeyData, "TLS key data.")
	fl.BoolVar(&a.MTLS, prefix+"mtls", a.MTLS, "Require clients to provide a client certificate.")
	fl.StringVar(&a.MTLSClientCAFile, prefix+"mtls-client-ca-file", a.MTLSClientCAFile, "Client CA file if not provided by the mtls auth plugin")
	fl.BoolVar(&a.Insecure, prefix+"insecure", a.Insecure, "Disable TLS.")
	fl.BoolVar(&a.MeshEnabled, prefix+"mesh-enabled", a.MeshEnabled, "Enable and register the MeshAPI.")
	fl.BoolVar(&a.AdminEnabled, prefix+"admin-enabled", a.AdminEnabled, "Enable and register the AdminAPI.")
}

// Validate validates the options.
func (a APIOptions) Validate() error {
	if a.Disabled {
		return nil
	}
	if a.ListenAddress == "" {
		return fmt.Errorf("services.api.listen-address must be set")
	}
	_, err := netip.ParseAddrPort(a.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen-address is invalid: %w", err)
	}
	if !a.Insecure {
		if (a.TLSCertFile == "" || a.TLSKeyFile == "") && (a.TLSCertData == "" || a.TLSKeyData == "") {
			return fmt.Errorf("tls-cert-file and tls-key-file or tls-cert-data and tls-key-data must be set")
		}
	}
	return nil
}

// ListenPort returns the listen port configured by these API options.
func (a APIOptions) ListenPort() uint16 {
	_, port, err := net.SplitHostPort(a.ListenAddress)
	if err != nil {
		return 0
	}
	out, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return uint16(out)
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
	fl.BoolVar(&w.Enabled, prefix+"enabled", w.Enabled, "Enable and register the WebRTC API.")
	fl.StringSliceVar(&w.STUNServers, prefix+"stun-servers", w.STUNServers, "TURN/STUN servers to use for the WebRTC API.")
}

// Validate validates the options.
func (w WebRTCOptions) Validate() error {
	if !w.Enabled {
		return nil
	}
	for _, srv := range w.STUNServers {
		srv = strings.TrimPrefix(srv, "turn:")
		srv = strings.TrimPrefix(srv, "stun:")
		_, _, err := net.SplitHostPort(srv)
		if err != nil {
			return fmt.Errorf("services.webrtc.stun-servers is invalid: %w", err)
		}
	}
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
	fl.BoolVar(&t.Enabled, prefix+"enabled", t.Enabled, "Enable TURN server.")
	fl.StringVar(&t.Endpoint, prefix+"endpoint", t.Endpoint, "TURN endpoint to advertise.")
	fl.StringVar(&t.PublicIP, prefix+"public-ip", t.PublicIP, "Public IP to advertise for STUN/TURN requests.")
	fl.StringVar(&t.ListenAddress, prefix+"listen-address", t.ListenAddress, "Address to listen on for STUN/TURN requests.")
	fl.StringVar(&t.Realm, prefix+"realm", t.Realm, "Realm used for TURN server authentication.")
	fl.StringVar(&t.TURNPortRange, prefix+"port-range", t.TURNPortRange, "Port range to use for TURN relays.")
}

// Validate values the TURN options.
func (t TURNOptions) Validate() error {
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
	if t.PublicIP == "" && t.Endpoint == "" {
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
func (t TURNOptions) ListenPort() uint16 {
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
	fl.BoolVar(&m.Enabled, prefix+"enabled", m.Enabled, "Enable mesh DNS.")
	fl.StringVar(&m.ListenUDP, prefix+"listen-udp", m.ListenUDP, "UDP address to listen on for DNS requests.")
	fl.StringVar(&m.ListenTCP, prefix+"isten-tcp", m.ListenTCP, "TCP address to listen on for DNS requests.")
	fl.IntVar(&m.ReusePort, prefix+"reuse-port", m.ReusePort, "Enable SO_REUSEPORT for mesh DNS. Only available on Linux systems.")
	fl.BoolVar(&m.EnableCompression, prefix+"compression", m.EnableCompression, "Enable DNS compression.")
	fl.DurationVar(&m.RequestTimeout, prefix+"request-timeout", m.RequestTimeout, "DNS request timeout.")
	fl.StringSliceVar(&m.Forwarders, prefix+"forwarders", m.Forwarders, "DNS forwarders (default = system resolvers).")
	fl.BoolVar(&m.SubscribeForwarders, prefix+"subscribe-forwarders", m.SubscribeForwarders, "Subscribe to new nodes that can forward requests.")
	fl.BoolVar(&m.DisableForwarding, prefix+"disable-forwarding", m.DisableForwarding, "Disable forwarding requests.")
	fl.IntVar(&m.CacheSize, prefix+"cache-size", m.CacheSize, "Size of the remote DNS cache (0 = disabled).")
	fl.BoolVar(&m.IPv6Only, prefix+"ipv6-only", m.IPv6Only, "Only respond to IPv6 requests.")
}

// ListenPort returns the listen port for the MeshDNS server is enabled.
func (m MeshDNSOptions) ListenPort() uint16 {
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

// Validate validates the options.
func (m MeshDNSOptions) Validate() error {
	if !m.Enabled {
		return nil
	}
	if m.ListenTCP == "" && m.ListenUDP == "" {
		return fmt.Errorf("services.meshdns.listen-tcp or services.meshdns.listen-udp must be set")
	}
	if m.ListenTCP != "" {
		_, _, err := net.SplitHostPort(m.ListenTCP)
		if err != nil {
			return fmt.Errorf("services.meshdns.listen-tcp is invalid: %w", err)
		}
	}
	if m.ListenUDP != "" {
		_, _, err := net.SplitHostPort(m.ListenUDP)
		if err != nil {
			return fmt.Errorf("services.meshdns.listen-udp is invalid: %w", err)
		}
	}
	if runtime.GOOS == "linux" {
		if m.ReusePort < 0 {
			return fmt.Errorf("services.meshdns.reuse-port must be >= 0")
		}
	} else if m.ReusePort != 0 && runtime.GOOS != "linux" {
		return fmt.Errorf("services.meshdns.reuse-port is only supported on Linux")
	}
	return nil
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
	fl.BoolVar(&m.Enabled, prefix+"enabled", m.Enabled, "Enable gRPC metrics.")
	fl.StringVar(&m.ListenAddress, prefix+"listen-address", m.ListenAddress, "gRPC metrics listen address.")
	fl.StringVar(&m.Path, prefix+"path", m.Path, "gRPC metrics path.")
}

// ListenPort returns the listen port for the Metrics server is enabled.
func (m MetricsOptions) ListenPort() uint16 {
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
func (m MetricsOptions) Validate() error {
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
func (o *ServiceOptions) RegisterAPIs(ctx context.Context, conn meshnode.Node, srv *services.Server, features []*v1.FeaturePort, storageMember bool) error {
	log := context.LoggerFrom(ctx)
	var rbacDisabled bool
	var err error
	maxTries := 5
	for i := 0; i < maxTries; i++ {
		rbacDisabled, err = conn.Storage().MeshDB().RBAC().GetEnabled(context.Background())
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
		rbacEvaluator = rbac.NewStoreEvaluator(conn.Storage().MeshDB())
	}
	// Always register the node API
	log.Debug("Registering node service")
	v1.RegisterNodeServer(srv, node.NewServer(ctx, node.Options{
		NodeID:     conn.ID(),
		NodeDialer: conn,
		Storage:    conn.Storage(),
		Meshnet:    conn.Network(),
		Plugins:    conn.Plugins(),
		Features:   features,
	}))
	// Register membership and storage if we are a storage provider
	if storageMember {
		log.Debug("Registering membership service")
		v1.RegisterMembershipServer(srv, membership.NewServer(ctx, membership.Options{
			NodeID:  conn.ID(),
			Storage: conn.Storage(),
			Plugins: conn.Plugins(),
			RBAC:    rbacEvaluator,
			Meshnet: conn.Network(),
		}))
		log.Debug("Registering storage service")
		storageSrv := storage.NewServer(ctx, conn.Storage(), rbacEvaluator, conn.Network())
		v1.RegisterStorageQueryServiceServer(srv, storageSrv)
	}
	// Register any other enabled APIs
	if o.API.MeshEnabled {
		log.Debug("Registering mesh api")
		v1.RegisterMeshServer(srv, meshapi.NewServer(conn.Storage().MeshDB()))
	}
	if o.WebRTC.Enabled {
		log.Debug("Registering WebRTC api")
		// Check if we are a TURN server, and if so - register the TURN server
		if o.TURN.Enabled {
			log.Debug("Registering local TURN server with WebRTC API")
			turnAddr := net.JoinHostPort(o.TURN.PublicIP, strconv.Itoa(int(o.TURN.ListenPort())))
			turnAddr = fmt.Sprintf("turn:%s", turnAddr)
			o.WebRTC.STUNServers = append([]string{turnAddr}, o.WebRTC.STUNServers...)
		}
		v1.RegisterWebRTCServer(srv, webrtc.NewServer(webrtc.Options{
			ID:          conn.ID(),
			Wireguard:   conn.Network().WireGuard(),
			NodeDialer:  conn,
			RBAC:        rbacEvaluator,
			STUNServers: o.WebRTC.STUNServers,
		}))
	}
	return nil
}

// NewFeatureSet returns a new FeatureSet for the given node options.
func (o *ServiceOptions) NewFeatureSet(grpcPort int, storagePort int, storageMember bool) []*v1.FeaturePort {
	// We always expose the node API
	var features []*v1.FeaturePort
	if !o.API.Disabled {
		features = append(features, &v1.FeaturePort{
			Feature: v1.Feature_NODES,
			Port:    int32(grpcPort),
		})
	}
	// If we are a raft member, we automatically serve storage and membership
	if storageMember {
		features = append(features, &v1.FeaturePort{
			Feature: v1.Feature_STORAGE_QUERIER,
			Port:    int32(grpcPort),
		})
		features = append(features, &v1.FeaturePort{
			Feature: v1.Feature_MEMBERSHIP,
			Port:    int32(grpcPort),
		})
		features = append(features, &v1.FeaturePort{
			Feature: v1.Feature_STORAGE_PROVIDER,
			Port:    int32(storagePort),
		})
	}
	if !o.API.Disabled {
		if !o.API.DisableLeaderProxy {
			features = append(features, &v1.FeaturePort{
				Feature: v1.Feature_LEADER_PROXY,
				Port:    int32(grpcPort),
			})
		}
		if o.API.MeshEnabled {
			features = append(features, &v1.FeaturePort{
				Feature: v1.Feature_MESH_API,
				Port:    int32(grpcPort),
			})
		}
		if o.API.AdminEnabled {
			features = append(features, &v1.FeaturePort{
				Feature: v1.Feature_ADMIN_API,
				Port:    int32(grpcPort),
			})
		}
		if o.WebRTC.Enabled {
			features = append(features, &v1.FeaturePort{
				Feature: v1.Feature_ICE_NEGOTIATION,
				Port:    int32(grpcPort),
			})
		}
	}
	if o.TURN.Enabled {
		features = append(features, &v1.FeaturePort{
			Feature: v1.Feature_TURN_SERVER,
			Port:    int32(o.TURN.ListenPort()),
		})
	}
	if o.MeshDNS.Enabled {
		features = append(features, &v1.FeaturePort{
			Feature: v1.Feature_MESH_DNS,
			Port:    int32(o.MeshDNS.ListenPort()),
		})
	}
	if o.Metrics.Enabled {
		features = append(features, &v1.FeaturePort{
			Feature: v1.Feature_METRICS,
			Port:    int32(o.Metrics.ListenPort()),
		})
	}
	return features
}

// NewServiceOptions returns new options for the webmesh services.
func (o *ServiceOptions) NewServiceOptions(ctx context.Context, conn meshnode.Node) (conf services.Options, err error) {
	if !o.API.Disabled {
		conf.ListenAddress = o.API.ListenAddress
		// Build out the server options
		if !o.API.Insecure {
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
		if o.Metrics.Enabled {
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

		if !o.API.DisableLeaderProxy {
			leaderProxy := leaderproxy.New(conn.ID(), conn.Storage().Consensus(), conn, conn.Network())
			unarymiddlewares = append(unarymiddlewares, leaderProxy.UnaryInterceptor())
			streammiddlewares = append(streammiddlewares, leaderProxy.StreamInterceptor())
		}

		conf.ServerOptions = append(conf.ServerOptions, grpc.ChainUnaryInterceptor(unarymiddlewares...))
		conf.ServerOptions = append(conf.ServerOptions, grpc.ChainStreamInterceptor(streammiddlewares...))
	} else {
		conf.DisableGRPC = true
	}
	// Append the enabled mesh services
	if o.MeshDNS.Enabled {
		dnsServer := meshdns.NewServer(ctx, &meshdns.Options{
			UDPListenAddr:     o.MeshDNS.ListenUDP,
			TCPListenAddr:     o.MeshDNS.ListenTCP,
			ReusePort:         o.MeshDNS.ReusePort,
			Compression:       o.MeshDNS.EnableCompression,
			RequestTimeout:    o.MeshDNS.RequestTimeout,
			Forwarders:        o.MeshDNS.Forwarders,
			DisableForwarding: o.MeshDNS.DisableForwarding,
			CacheSize:         o.MeshDNS.CacheSize,
		})
		// Automatically register the local domain
		err := dnsServer.RegisterDomain(meshdns.DomainOptions{
			NodeID:              conn.ID(),
			MeshDomain:          conn.Domain(),
			MeshStorage:         conn.Storage(),
			IPv6Only:            o.MeshDNS.IPv6Only,
			SubscribeForwarders: o.MeshDNS.SubscribeForwarders,
		})
		if err != nil {
			return conf, err
		}
		conf.Servers = append(conf.Servers, dnsServer)
	}
	if o.TURN.Enabled {
		turnServer := turn.NewServer(ctx, turn.Options{
			PublicIP:  o.TURN.PublicIP,
			ListenUDP: o.TURN.ListenAddress,
			Realm:     o.TURN.Realm,
			PortRange: o.TURN.TURNPortRange,
		})
		conf.Servers = append(conf.Servers, turnServer)
	}
	if o.Metrics.Enabled {
		metricsServer := metrics.New(ctx, metrics.Options{
			ListenAddress: o.Metrics.ListenAddress,
			Path:          o.Metrics.Path,
		})
		conf.Servers = append(conf.Servers, metricsServer)
	}
	return
}

// NewServerTLSOptions returns new TLS options for the gRPC server.
func (o *ServiceOptions) NewServerTLSOptions() (grpc.ServerOption, error) {
	tlsConfig := &tls.Config{}
	if o.API.TLSCertFile != "" && o.API.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(o.API.TLSCertFile, o.API.TLSKeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	if o.API.TLSCertData != "" && o.API.TLSKeyData != "" {
		certData, err := base64.StdEncoding.DecodeString(o.API.TLSCertData)
		if err != nil {
			return nil, err
		}
		keyData, err := base64.StdEncoding.DecodeString(o.API.TLSKeyData)
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
	if o.API.MTLS {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		if o.API.MTLSClientCAFile != "" {
			// This happens in external cases where the mtls plugin is not being used.
			pool := x509.NewCertPool()
			caCert, err := os.ReadFile(o.API.MTLSClientCAFile)
			if err != nil {
				return nil, err
			}
			if !pool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse client CA certificate")
			}
			tlsConfig.ClientCAs = pool
		}
	}
	return grpc.Creds(credentials.NewTLS(tlsConfig)), nil
}

// InterceptorLogger returns a logging.Logger that logs to the given slog.Logger.
func InterceptorLogger() logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		log := context.LoggerFrom(ctx)
		if msg == "started call" {
			msg = "Started gRPC call"
		}
		if msg == "finished call" {
			msg = "Finished gRPC call"
		}
		log.Log(ctx, slog.Level(lvl), msg, fields...)
	})
}
