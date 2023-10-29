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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/multiformats/go-multiaddr"
	"github.com/spf13/pflag"
	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshnet"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport/libp2p"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport/tcp"
	"github.com/webmeshproj/webmesh/pkg/meshnode"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins/basicauth"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins/idauth"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins/ldap"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/services/meshdns"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// MeshOptions are the options for participating in a mesh.
type MeshOptions struct {
	// NodeID is the node ID.
	NodeID string `koanf:"node-id,omitempty"`
	// PrimaryEndpoint is the primary endpoint to advertise when joining.
	// This can be empty to signal the node is not publicly reachable.
	PrimaryEndpoint string `koanf:"primary-endpoint,omitempty"`
	// ZoneAwarenessID is the zone awareness ID.
	ZoneAwarenessID string `koanf:"zone-awareness-id,omitempty"`
	// JoinAddresses are addresses of nodes to attempt to join.
	JoinAddresses []string `koanf:"join-addresses,omitempty"`
	// JoinMultiaddrs are multiaddresses to attempt to join over libp2p.
	// These cannot be used with JoinAddresses.
	JoinMultiaddrs []string `koanf:"join-multiaddrs,omitempty"`
	// MaxJoinRetries is the maximum number of join retries.
	MaxJoinRetries int `koanf:"max-join-retries,omitempty"`
	// Routes are additional routes to advertise to the mesh. These routes are advertised to all peers.
	// If the node is not allowed to put routes in the mesh, the node will be unable to join.
	Routes []string `koanf:"routes,omitempty"`
	// ICEPeers are peers to request direct edges to over ICE. If the node is not allowed to create edges
	// and data channels, the node will be unable to join.
	ICEPeers []string `koanf:"ice-peers,omitempty"`
	// LibP2PPeers are peers to request direct edges to over libp2p. If the node is not allowed to create edges
	// and data channels, the node will be unable to join.
	LibP2PPeers []string `koanf:"libp2p-peers,omitempty"`
	// GRPCAdvertisePort is the port to advertise for gRPC.
	GRPCAdvertisePort int `koanf:"grpc-advertise-port,omitempty"`
	// MeshDNSAdvertisePort is the port to advertise for DNS.
	MeshDNSAdvertisePort int `koanf:"meshdns-advertise-port,omitempty"`
	// UseMeshDNS indicates whether to set mesh DNS servers to the system configuration.
	UseMeshDNS bool `koanf:"use-meshdns,omitempty"`
	// RequestVote is true if the node should can provide storage and consensus.
	RequestVote bool `koanf:"request-vote,omitempty"`
	// RequestObserver is true if the node should be a storage observer.
	RequestObserver bool `koanf:"request-observer,omitempty"`
	// StoragePreferIPv6 is the prefer IPv6 flag for storage provider connections.
	StoragePreferIPv6 bool `koanf:"prefer-ipv6,omitempty"`
	// DisableIPv4 disables IPv4 usage.
	DisableIPv4 bool `koanf:"disable-ipv4,omitempty"`
	// DisableIPv6 disables IPv6 usage.
	DisableIPv6 bool `koanf:"disable-ipv6,omitempty"`
	// DisableFeatureAdvertisement is true if feature advertisement should be disabled.
	DisableFeatureAdvertisement bool `koanf:"disable-feature-advertisement,omitempty"`
	// DisableDefaultIPAM is true if the default IPAM should be disabled.
	DisableDefaultIPAM bool `koanf:"disable-default-ipam,omitempty"`
	// DefaultIPAMStaticIPv4 are static IPv4 assignments to use for the default IPAM.
	DefaultIPAMStaticIPv4 map[string]string `koanf:"default-ipam-static-ipv4,omitempty"`
}

// NewMeshOptions returns a new MeshOptions with the default values. If node id
// is empty it will be assumed from the system or generated.
func NewMeshOptions(nodeID string) MeshOptions {
	return MeshOptions{
		NodeID:                      nodeID,
		PrimaryEndpoint:             "",
		ZoneAwarenessID:             "",
		JoinAddresses:               nil,
		MaxJoinRetries:              15,
		Routes:                      nil,
		ICEPeers:                    []string{},
		LibP2PPeers:                 []string{},
		GRPCAdvertisePort:           services.DefaultGRPCPort,
		MeshDNSAdvertisePort:        meshdns.DefaultAdvertisePort,
		UseMeshDNS:                  false,
		RequestVote:                 false,
		RequestObserver:             false,
		StoragePreferIPv6:           false,
		DisableIPv4:                 false,
		DisableIPv6:                 false,
		DisableFeatureAdvertisement: false,
		DisableDefaultIPAM:          false,
		DefaultIPAMStaticIPv4:       map[string]string{},
	}
}

// BindFlags binds the flags to the options.
func (o *MeshOptions) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.StringVar(&o.NodeID, prefix+"node-id", o.NodeID, "Node ID. One will be chosen automatically if left unset.")
	fs.StringVar(&o.PrimaryEndpoint, prefix+"primary-endpoint", o.PrimaryEndpoint, "Primary endpoint to advertise when joining.")
	fs.StringVar(&o.ZoneAwarenessID, prefix+"zone-awareness-id", o.ZoneAwarenessID, "Zone awareness ID.")
	fs.StringSliceVar(&o.JoinAddresses, prefix+"join-addresses", o.JoinAddresses, "Addresses of nodes to join.")
	fs.StringSliceVar(&o.JoinMultiaddrs, prefix+"join-multiaddrs", o.JoinMultiaddrs, "Multiaddresses of nodes to join.")
	fs.IntVar(&o.MaxJoinRetries, prefix+"max-join-retries", o.MaxJoinRetries, "Maximum number of join retries.")
	fs.StringSliceVar(&o.Routes, prefix+"routes", o.Routes, "Additional routes to advertise to the mesh.")
	fs.StringSliceVar(&o.ICEPeers, prefix+"ice-peers", o.ICEPeers, "Peers to request direct edges to over ICE.")
	fs.StringSliceVar(&o.LibP2PPeers, prefix+"libp2p-peers", o.LibP2PPeers, "Map of peer IDs to rendezvous strings for edges over libp2p.")
	fs.IntVar(&o.GRPCAdvertisePort, prefix+"grpc-advertise-port", o.GRPCAdvertisePort, "Port to advertise for gRPC.")
	fs.IntVar(&o.MeshDNSAdvertisePort, prefix+"meshdns-advertise-port", o.MeshDNSAdvertisePort, "Port to advertise for DNS.")
	fs.BoolVar(&o.UseMeshDNS, prefix+"use-meshdns", o.UseMeshDNS, "Set mesh DNS servers to the system configuration.")
	fs.BoolVar(&o.RequestVote, prefix+"request-vote", o.RequestVote, "Request a vote in elections for the storage backend.")
	fs.BoolVar(&o.RequestObserver, prefix+"request-observer", o.RequestObserver, "Request to be an observer in the storage backend.")
	fs.BoolVar(&o.StoragePreferIPv6, prefix+"storage-prefer-ipv6", o.StoragePreferIPv6, "Prefer IPv6 connections for the storage backend transport.")
	fs.BoolVar(&o.DisableIPv4, prefix+"disable-ipv4", o.DisableIPv4, "Disable IPv4 usage.")
	fs.BoolVar(&o.DisableIPv6, prefix+"disable-ipv6", o.DisableIPv6, "Disable IPv6 usage.")
	fs.BoolVar(&o.DisableFeatureAdvertisement, prefix+"disable-feature-advertisement", o.DisableFeatureAdvertisement, "Disable feature advertisement.")
	fs.BoolVar(&o.DisableDefaultIPAM, prefix+"disable-default-ipam", o.DisableDefaultIPAM, "Disable the default IPAM.")
	fs.StringToStringVar(&o.DefaultIPAMStaticIPv4, prefix+"default-ipam-static-ipv4", o.DefaultIPAMStaticIPv4, "Static IPv4 assignments to use for the default IPAM.")
}

// Validate validates the options.
func (o *MeshOptions) Validate() error {
	if o == nil {
		return fmt.Errorf("mesh options are required")
	}
	if o.NodeID != "" {
		if !types.IsValidNodeID(o.NodeID) {
			return fmt.Errorf("invalid node ID")
		}
	}
	if o.DisableIPv4 && o.DisableIPv6 {
		return fmt.Errorf("cannot disable both IPv4 and IPv6")
	}
	if (len(o.JoinAddresses) > 0 || len(o.JoinMultiaddrs) > 0) && o.MaxJoinRetries <= 0 {
		return fmt.Errorf("max join retries must be >= 0")
	}
	for _, addr := range o.JoinAddresses {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("invalid join address: %w", err)
		}
	}
	for _, addr := range o.JoinMultiaddrs {
		_, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			return fmt.Errorf("invalid join multiaddress: %w", err)
		}
	}
	if o.RequestVote && o.RequestObserver {
		return fmt.Errorf("cannot request vote and observer")
	}
	if o.DisableIPv6 && o.StoragePreferIPv6 {
		return fmt.Errorf("cannot prefer IPv6 for storage when IPv6 is disabled")
	}
	if o.PrimaryEndpoint != "" {
		// Add a dummy port to the primary endpoint
		var epstr string
		ip, err := netip.ParseAddr(o.PrimaryEndpoint)
		if err == nil {
			if ip.Is4() {
				epstr = fmt.Sprintf("%s:0", ip.String())
			} else {
				epstr = fmt.Sprintf("[%s]:0", ip.String())
			}
		} else {
			// Assume it's a hostname
			epstr = fmt.Sprintf("%s:0", o.PrimaryEndpoint)
		}
		_, _, err = net.SplitHostPort(epstr)
		if err != nil {
			return fmt.Errorf("invalid primary endpoint: %w", err)
		}
	}
	for _, peer := range o.ICEPeers {
		if !types.IsValidNodeID(peer) {
			return fmt.Errorf("invalid ICE peer ID %s", peer)
		}
	}
	for _, peer := range o.LibP2PPeers {
		if !types.IsValidNodeID(peer) {
			return fmt.Errorf("invalid libp2p peer ID %s", peer)
		}
	}
	if !o.DisableFeatureAdvertisement {
		if o.GRPCAdvertisePort <= 0 || o.GRPCAdvertisePort > 65535 {
			return fmt.Errorf("invalid gRPC advertise port")
		}
		if o.MeshDNSAdvertisePort <= 0 || o.MeshDNSAdvertisePort > 65535 {
			return fmt.Errorf("invalid mesh DNS advertise port")
		}
	}
	if !o.DisableDefaultIPAM {
		for id, addr := range o.DefaultIPAMStaticIPv4 {
			if !types.IsValidNodeID(id) {
				return fmt.Errorf("invalid node ID %s", id)
			}
			_, err := netip.ParsePrefix(addr)
			if err != nil {
				return fmt.Errorf("invalid IPv4 address %s for node %s", addr, id)
			}
		}
	}
	return nil
}

// IsStorageMember returns true if the node is a storage provider.
func (o *Config) IsStorageMember() bool {
	return o.Bootstrap.Enabled || o.Mesh.RequestVote || o.Mesh.RequestObserver
}

// NewMeshConfig return a new Mesh configuration based on the node configuration.
// The key is optional and will be taken from the configuration if not provided.
func (o *Config) NewMeshConfig(ctx context.Context, key crypto.PrivateKey) (conf meshnode.Config, err error) {
	log := context.LoggerFrom(ctx)
	if key == nil {
		key, err = o.WireGuard.LoadKey(ctx)
		if err != nil {
			return
		}
	}
	conf = meshnode.Config{
		Key:                     key,
		HeartbeatPurgeThreshold: o.Storage.Raft.HeartbeatPurgeThreshold,
		ZoneAwarenessID:         o.Mesh.ZoneAwarenessID,
		UseMeshDNS:              o.Mesh.UseMeshDNS,
		DisableIPv4:             o.Mesh.DisableIPv4,
		DisableIPv6:             o.Mesh.DisableIPv6,
		DisableDefaultIPAM:      o.Mesh.DisableDefaultIPAM,
		DefaultIPAMStaticIPv4:   o.Mesh.DefaultIPAMStaticIPv4,
	}
	// Check if we are serving a local DNS server
	if o.Services.MeshDNS.Enabled {
		_, port, err := net.SplitHostPort(o.Services.MeshDNS.ListenUDP)
		if err != nil {
			return conf, fmt.Errorf("parse mesh DNS UDP listen address: %w", err)
		}
		log.Debug("Using local mesh DNS server", slog.String("port", port))
		conf.LocalMeshDNSAddr = net.JoinHostPort("127.0.0.1", port)
	}
	// Check what dial options we need
	conf.Credentials, err = o.NewClientCredentials(ctx, key)
	if err != nil {
		return
	}
	conf.NodeID, err = o.NodeID(ctx)
	if err != nil {
		return
	}
	return
}

// NewClientCredentials build new client credentials from the given configuration.
func (o *Config) NewClientCredentials(ctx context.Context, key crypto.PrivateKey) ([]grpc.DialOption, error) {
	var creds []grpc.DialOption
	log := context.LoggerFrom(ctx)
	if !o.TLS.Insecure {
		// We need a TLS configuration
		log.Debug("Configuring secure gRPC transport")
		tlsconf := &tls.Config{}
		var roots *x509.CertPool
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		var ca *x509.Certificate
		if o.TLS.CAFile != "" {
			// Load the CA file
			log.Debug("Loading CA file", slog.String("file", o.TLS.CAFile))
			ca, err = crypto.DecodeTLSCertificateFromFile(o.TLS.CAFile)
			if err != nil {
				return nil, fmt.Errorf("read CA file: %w", err)
			}
			roots.AddCert(ca)
		}
		if o.TLS.CAData != "" {
			// Load the CA data
			pemdata, err := base64.StdEncoding.DecodeString(o.TLS.CAData)
			if err != nil {
				return nil, fmt.Errorf("decode CA data: %w", err)
			}
			ca, err = crypto.DecodeTLSCertificate(bytes.NewReader(pemdata))
			if err != nil {
				return nil, fmt.Errorf("read CA data: %w", err)
			}
			roots.AddCert(ca)
		}
		tlsconf.RootCAs = roots
		if o.TLS.InsecureSkipVerify {
			log.Warn("InsecureSkipVerify is enabled, skipping TLS verification")
			tlsconf.InsecureSkipVerify = true
		}
		if o.TLS.VerifyChainOnly {
			if ca == nil {
				// This shouldn't have happened
				return nil, fmt.Errorf("verify chain only is enabled but no CA was provided")
			}
			log.Warn("VerifyChainOnly is enabled, only verifying the certificate chain")
			tlsconf.InsecureSkipVerify = true
			tlsconf.VerifyPeerCertificate = crypto.VerifyCertificateChainOnly([]*x509.Certificate{ca})
		}
		// Check if we are using mutual TLS
		if !o.Auth.MTLS.IsEmpty() {
			log.Debug("Configuring mutual TLS")
			var cert tls.Certificate
			if o.Auth.MTLS.CertFile != "" && o.Auth.MTLS.KeyFile != "" {
				log.Debug("Loading client certificate", slog.String("file", o.Auth.MTLS.CertFile), slog.String("key", o.Auth.MTLS.KeyFile))
				cert, err = tls.LoadX509KeyPair(o.Auth.MTLS.CertFile, o.Auth.MTLS.KeyFile)
				if err != nil {
					return nil, fmt.Errorf("load client certificate: %w", err)
				}
			}
			if o.Auth.MTLS.CertData != "" && o.Auth.MTLS.KeyData != "" {
				certData, err := base64.StdEncoding.DecodeString(o.Auth.MTLS.CertData)
				if err != nil {
					return nil, fmt.Errorf("decode client certificate: %w", err)
				}
				keyData, err := base64.StdEncoding.DecodeString(o.Auth.MTLS.KeyData)
				if err != nil {
					return nil, fmt.Errorf("decode client key: %w", err)
				}
				cert, err = tls.X509KeyPair(certData, keyData)
				if err != nil {
					return nil, fmt.Errorf("load client certificate: %w", err)
				}
			}
			tlsconf.Certificates = []tls.Certificate{cert}
		}
		// Append the configuration to the dial options
		creds = append(creds, grpc.WithTransportCredentials(credentials.NewTLS(tlsconf)))
	} else {
		log.Warn("Insecure is enabled, not using a TLS transport")
		// Make sure we are using insecure credentials
		creds = append(creds, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	// Check for per-rpc credentials
	if !o.Auth.Basic.IsEmpty() {
		log.Debug("Configuring basic authentication")
		creds = append(creds, basicauth.NewCreds(o.Auth.Basic.Username, o.Auth.Basic.Password))
	}
	if !o.Auth.LDAP.IsEmpty() {
		log.Debug("Configuring LDAP authentication")
		creds = append(creds, ldap.NewCreds(o.Auth.LDAP.Username, o.Auth.LDAP.Password))
	}
	if o.Auth.IDAuth.Enabled {
		log.Debug("Configuring ID authentication")
		creds = append(creds, idauth.NewCreds(key))
		// Make sure our ID is set if it hasn't been
		o.Mesh.NodeID = key.ID()
	}
	return creds, nil
}

// NewConnectOptions returns new connection options for the configuration. The given raft node must
// be started before it can be used. Host can be nil and if one is needed it will be created.
func (o *Config) NewConnectOptions(ctx context.Context, conn meshnode.Node, provider storage.Provider, host libp2p.Host) (opts meshnode.ConnectOptions, err error) {
	// Determine our node ID
	nodeid, err := o.NodeID(ctx)
	if err != nil {
		return
	}
	// Parse all endpoints and routes
	var primaryEndpoint netip.Addr
	if o.Mesh.PrimaryEndpoint != "" {
		primaryEndpoint, err = netip.ParseAddr(o.Mesh.PrimaryEndpoint)
		if err != nil {
			return
		}
	}
	var wireguardEndpoints []netip.AddrPort
	if primaryEndpoint.IsValid() {
		// Place it at the top
		wireguardEndpoints = append(wireguardEndpoints, netip.AddrPortFrom(primaryEndpoint, uint16(o.WireGuard.ListenPort)))
	}
	if len(o.WireGuard.Endpoints) > 0 {
		for _, ep := range o.WireGuard.Endpoints {
			if primaryEndpoint.IsValid() && strings.HasPrefix(ep, primaryEndpoint.String()) {
				// Skip the primary endpoint
				continue
			}
			var addr netip.AddrPort
			addr, err = netip.ParseAddrPort(ep)
			if err != nil {
				return
			}
			if addr.IsValid() {
				wireguardEndpoints = append(wireguardEndpoints, addr)
			}
		}
	}
	var routes []netip.Prefix
	if len(o.Mesh.Routes) > 0 {
		routes = make([]netip.Prefix, len(o.Mesh.Routes))
		for i, r := range o.Mesh.Routes {
			routes[i], err = netip.ParsePrefix(r)
			if err != nil {
				return
			}
		}
	}
	// Create the join transport
	joinRT, err := o.NewJoinTransport(ctx, nodeid, conn, host)
	if err != nil {
		return
	}
	// Configure any bootstrap options
	var bootstrap *meshnode.BootstrapOptions
	if o.Bootstrap.Enabled {
		rt, err := o.NewBootstrapTransport(ctx, nodeid, conn, host)
		if err != nil {
			return opts, fmt.Errorf("create bootstrap transport: %w", err)
		}
		var bootstrapServers []string
		for id := range o.Bootstrap.Transport.TCPServers {
			if id == nodeid {
				continue
			}
			bootstrapServers = append(bootstrapServers, id)
		}
		bootstrap = &meshnode.BootstrapOptions{
			Transport:            rt,
			IPv4Network:          o.Bootstrap.IPv4Network,
			IPv6Network:          o.Bootstrap.IPv6Network,
			MeshDomain:           o.Bootstrap.MeshDomain,
			Admin:                o.Bootstrap.Admin,
			Servers:              bootstrapServers,
			Voters:               o.Bootstrap.Voters,
			DisableRBAC:          o.Bootstrap.DisableRBAC,
			DefaultNetworkPolicy: o.Bootstrap.DefaultNetworkPolicy,
			Force:                o.Bootstrap.Force,
		}
	}
	// Create our plugins
	plugins, err := o.Plugins.NewPluginSet(ctx)
	if err != nil {
		return
	}
	// Determine the local DNS address if enabled.
	var localDNSAddr netip.AddrPort
	if o.Services.MeshDNS.Enabled {
		localDNSAddr, err = netip.ParseAddrPort(o.Services.MeshDNS.ListenUDP)
		if err != nil {
			return
		}
		localDNSAddr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), localDNSAddr.Port())
	}
	// Create the options
	opts = meshnode.ConnectOptions{
		StorageProvider:      provider,
		JoinRoundTripper:     joinRT,
		LeaveRoundTripper:    o.NewLeaveTransport(ctx, conn),
		Features:             o.Services.NewFeatureSet(provider, o.Services.API.ListenPort()),
		Bootstrap:            bootstrap,
		MaxJoinRetries:       o.Mesh.MaxJoinRetries,
		GRPCAdvertisePort:    o.Mesh.GRPCAdvertisePort,
		MeshDNSAdvertisePort: o.Mesh.MeshDNSAdvertisePort,
		PrimaryEndpoint:      primaryEndpoint,
		WireGuardEndpoints:   wireguardEndpoints,
		RequestVote:          o.Mesh.RequestVote,
		RequestObserver:      o.Mesh.RequestObserver,
		Routes:               routes,
		DirectPeers: func() map[types.NodeID]v1.ConnectProtocol {
			peers := make(map[types.NodeID]v1.ConnectProtocol)
			for _, peer := range o.Mesh.ICEPeers {
				p := peer
				peers[types.NodeID(p)] = v1.ConnectProtocol_CONNECT_ICE
			}
			for _, peer := range o.Mesh.LibP2PPeers {
				p := peer
				peers[types.NodeID(p)] = v1.ConnectProtocol_CONNECT_LIBP2P
			}
			return peers
		}(),
		PreferIPv6: o.Mesh.StoragePreferIPv6,
		Plugins:    plugins,
		NetworkOptions: meshnet.Options{
			Modprobe:              o.WireGuard.Modprobe,
			InterfaceName:         o.WireGuard.InterfaceName,
			ForceReplace:          o.WireGuard.ForceInterfaceName,
			ListenPort:            o.WireGuard.ListenPort,
			PersistentKeepAlive:   o.WireGuard.PersistentKeepAlive,
			ForceTUN:              o.WireGuard.ForceTUN,
			MTU:                   o.WireGuard.MTU,
			RecordMetrics:         o.WireGuard.RecordMetrics,
			RecordMetricsInterval: o.WireGuard.RecordMetricsInterval,
			StoragePort:           o.Storage.ListenPort(),
			GRPCPort:              o.Mesh.GRPCAdvertisePort,
			ZoneAwarenessID:       o.Mesh.ZoneAwarenessID,
			DialOptions:           conn.Credentials(),
			LocalDNSAddr:          localDNSAddr,
			DisableIPv4:           o.Mesh.DisableIPv4,
			DisableIPv6:           o.Mesh.DisableIPv6,
			DisableFullTunnel:     o.WireGuard.DisableFullTunnel,
			Relays: meshnet.RelayOptions{
				Host: o.Discovery.HostOptions(ctx, conn.Key()),
			},
		},
	}
	return
}

func (o *Config) NewLeaveTransport(ctx context.Context, conn meshnode.Node) transport.LeaveRoundTripper {
	return transport.LeaveRoundTripperFunc(func(ctx context.Context, req *v1.LeaveRequest) (*v1.LeaveResponse, error) {
		c, err := conn.DialLeader(ctx)
		if err != nil {
			return nil, fmt.Errorf("dial leader: %w", err)
		}
		defer c.Close()
		client := v1.NewMembershipClient(c)
		return client.Leave(ctx, req)
	})
}

func (o *Config) NewJoinTransport(ctx context.Context, nodeID string, conn meshnode.Node, host libp2p.Host) (transport.JoinRoundTripper, error) {
	if o.Bootstrap.Enabled {
		// Our join transport is the gRPC transport to other bootstrap nodes
		var addrs []string
		for id, addr := range o.Bootstrap.Transport.TCPServers {
			if id == nodeID {
				continue
			}
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid bootstrap server address: %w", err)
			}
			var addr string
			if len(o.Bootstrap.Transport.ServerGRPCPorts) > 0 && o.Bootstrap.Transport.ServerGRPCPorts[host] != 0 {
				addr = net.JoinHostPort(host, fmt.Sprintf("%d", o.Bootstrap.Transport.ServerGRPCPorts[host]))
			} else {
				// Assume the default port
				addr = net.JoinHostPort(host, fmt.Sprintf("%d", services.DefaultGRPCPort))
			}
			addrs = append(addrs, addr)
		}
		return tcp.NewJoinRoundTripper(tcp.RoundTripOptions{
			Addrs:          addrs,
			Credentials:    conn.Credentials(),
			AddressTimeout: time.Second * 3,
		}), nil
	}
	if len(o.Mesh.JoinAddresses) > 0 {
		return tcp.NewJoinRoundTripper(tcp.RoundTripOptions{
			Addrs:          o.Mesh.JoinAddresses,
			Credentials:    conn.Credentials(),
			AddressTimeout: time.Second * 3,
		}), nil
	}
	if len(o.Mesh.JoinMultiaddrs) > 0 {
		joinTransport, err := libp2p.NewJoinRoundTripper(ctx, libp2p.RoundTripOptions{
			Host:        host,
			Multiaddrs:  libp2p.ToMultiaddrs(o.Mesh.JoinMultiaddrs),
			HostOptions: o.Discovery.HostOptions(ctx, conn.Key()),
			Credentials: conn.Credentials(),
		})
		if err != nil {
			return nil, fmt.Errorf("create libp2p join transport: %w", err)
		}
		return joinTransport, nil
	}
	if o.Discovery.Discover {
		joinTransport, err := libp2p.NewDiscoveryJoinRoundTripper(ctx, libp2p.RoundTripOptions{
			Host:        host,
			Rendezvous:  o.Discovery.Rendezvous,
			HostOptions: o.Discovery.HostOptions(ctx, conn.Key()),
			Credentials: conn.Credentials(),
		})
		if err != nil {
			return nil, fmt.Errorf("create libp2p join transport: %w", err)
		}
		return joinTransport, nil
	}
	// A nil transport is technically okay, it means we are a single-node mesh
	return nil, nil
}
