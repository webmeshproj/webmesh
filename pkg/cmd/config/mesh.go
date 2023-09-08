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
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/multiformats/go-multiaddr"
	"github.com/spf13/pflag"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/mesh"
	meshnet "github.com/webmeshproj/webmesh/pkg/net"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/net/transport/libp2p"
	"github.com/webmeshproj/webmesh/pkg/net/transport/tcp"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins/basicauth"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins/ldap"
	"github.com/webmeshproj/webmesh/pkg/raft"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/services/meshdns"
	"github.com/webmeshproj/webmesh/pkg/util/netutil"
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
	// JoinAddress is the address of a node to join.
	JoinAddress string `koanf:"join-address,omitempty"`
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
	// DisableIPv4 disables IPv4 usage.
	DisableIPv4 bool `koanf:"disable-ipv4,omitempty"`
	// DisableIPv6 disables IPv6 usage.
	DisableIPv6 bool `koanf:"disable-ipv6,omitempty"`
	// DisableFeatureAdvertisement is true if feature advertisement should be disabled.
	DisableFeatureAdvertisement bool `koanf:"disable-feature-advertisement,omitempty"`
}

// NewMeshOptions returns a new MeshOptions with the default values. If node id
// is empty it will be assumed from the system or generated.
func NewMeshOptions(nodeID string) MeshOptions {
	return MeshOptions{
		NodeID:                      nodeID,
		PrimaryEndpoint:             "",
		ZoneAwarenessID:             "",
		JoinAddress:                 "",
		MaxJoinRetries:              15,
		Routes:                      nil,
		GRPCAdvertisePort:           services.DefaultGRPCPort,
		MeshDNSAdvertisePort:        meshdns.DefaultAdvertisePort,
		UseMeshDNS:                  false,
		DisableIPv4:                 false,
		DisableIPv6:                 false,
		DisableFeatureAdvertisement: false,
	}
}

// BindFlags binds the flags to the options.
func (o *MeshOptions) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.StringVar(&o.NodeID, prefix+"mesh.node-id", "", "Node ID. One will be chosen automatically if left unset.")
	fs.StringVar(&o.PrimaryEndpoint, prefix+"mesh.primary-endpoint", "", "Primary endpoint to advertise when joining.")
	fs.StringVar(&o.ZoneAwarenessID, prefix+"mesh.zone-awareness-id", "", "Zone awareness ID.")
	fs.StringVar(&o.JoinAddress, prefix+"mesh.join-address", "", "Address of a node to join.")
	fs.IntVar(&o.MaxJoinRetries, prefix+"mesh.max-join-retries", 15, "Maximum number of join retries.")
	fs.StringSliceVar(&o.Routes, prefix+"mesh.routes", nil, "Additional routes to advertise to the mesh.")
	fs.StringSliceVar(&o.ICEPeers, prefix+"mesh.ice-peers", nil, "Peers to request direct edges to over ICE.")
	fs.StringSliceVar(&o.LibP2PPeers, prefix+"mesh.libp2p-peers", nil, "Map of peer IDs to rendezvous strings for edges over libp2p.")
	fs.IntVar(&o.GRPCAdvertisePort, prefix+"mesh.grpc-advertise-port", services.DefaultGRPCPort, "Port to advertise for gRPC.")
	fs.IntVar(&o.MeshDNSAdvertisePort, prefix+"mesh.meshdns-advertise-port", meshdns.DefaultAdvertisePort, "Port to advertise for DNS.")
	fs.BoolVar(&o.UseMeshDNS, prefix+"mesh.use-meshdns", false, "Set mesh DNS servers to the system configuration.")
	fs.BoolVar(&o.DisableIPv4, prefix+"mesh.disable-ipv4", false, "Disable IPv4 usage.")
	fs.BoolVar(&o.DisableIPv6, prefix+"mesh.disable-ipv6", false, "Disable IPv6 usage.")
	fs.BoolVar(&o.DisableFeatureAdvertisement, prefix+"mesh.disable-feature-advertisement", false, "Disable feature advertisement.")
}

// Validate validates the options.
func (o *MeshOptions) Validate() error {
	if o.DisableIPv4 && o.DisableIPv6 {
		return fmt.Errorf("cannot disable both IPv4 and IPv6")
	}
	if o.JoinAddress != "" && o.MaxJoinRetries < 0 {
		return fmt.Errorf("max join retries must be >= 0")
	}
	if o.PrimaryEndpoint != "" {
		// Add a dummy port to the primary endpoint
		ep := net.JoinHostPort(o.PrimaryEndpoint, "0")
		_, _, err := net.SplitHostPort(ep)
		if err != nil {
			return fmt.Errorf("invalid primary endpoint: %w", err)
		}
	}
	if o.GRPCAdvertisePort <= 1024 {
		return fmt.Errorf("invalid gRPC advertise port")
	}
	return nil
}

// NewMeshConfig return a new Mesh configuration based on the node configuration.
// The key is optional and will be taken from the configuration if not provided.
func (o *Config) NewMeshConfig(ctx context.Context, key crypto.PrivateKey) (conf mesh.Config, err error) {
	log := context.LoggerFrom(ctx)
	nodeid, err := o.NodeID()
	if err != nil {
		return
	}
	if key == nil {
		key, err = o.LoadKey(ctx)
		if err != nil {
			return
		}
	}
	conf = mesh.Config{
		NodeID:                  nodeid,
		Key:                     key,
		HeartbeatPurgeThreshold: o.Raft.HeartbeatPurgeThreshold,
		ZoneAwarenessID:         o.Mesh.ZoneAwarenessID,
		UseMeshDNS:              o.Mesh.UseMeshDNS,
		DisableIPv4:             o.Mesh.DisableIPv4,
		DisableIPv6:             o.Mesh.DisableIPv6,
		LocalMeshDNSAddr:        "",
		Credentials:             []grpc.DialOption{},
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
	if !o.TLS.Insecure {
		// We need a TLS configuration
		log.Debug("Configuring secure gRPC transport")
		var tlsconf tls.Config
		var roots *x509.CertPool
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if o.TLS.CAFile != "" {
			// Load the CA file
			log.Debug("Loading CA file", slog.String("file", o.TLS.CAFile))
			ca, err := os.ReadFile(o.TLS.CAFile)
			if err != nil {
				return conf, fmt.Errorf("read CA file: %w", err)
			}
			// Add the CA to the roots
			if !roots.AppendCertsFromPEM(ca) {
				return conf, fmt.Errorf("add CA to roots")
			}
		}
		if o.TLS.CAData != "" {
			ca, err := base64.StdEncoding.DecodeString(o.TLS.CAData)
			if err != nil {
				return conf, fmt.Errorf("decode CA data: %w", err)
			}
			// Add the CA to the roots
			if !roots.AppendCertsFromPEM(ca) {
				return conf, fmt.Errorf("add CA to roots")
			}
		}
		tlsconf.RootCAs = roots
		if o.TLS.InsecureSkipVerify {
			log.Warn("InsecureSkipVerify is enabled, skipping TLS verification")
			tlsconf.InsecureSkipVerify = true
		}
		if o.TLS.VerifyChainOnly {
			tlsconf.VerifyPeerCertificate = netutil.VerifyChainOnly
		}
		// Check if we are using mutual TLS
		if o.Auth.MTLS != (MTLSOptions{}) {
			log.Debug("Configuring mutual TLS")
			var cert tls.Certificate
			if o.Auth.MTLS.CertFile != "" && o.Auth.MTLS.KeyFile != "" {
				log.Debug("Loading client certificate", slog.String("file", o.Auth.MTLS.CertFile), slog.String("key", o.Auth.MTLS.KeyFile))
				cert, err = tls.LoadX509KeyPair(o.Auth.MTLS.CertFile, o.Auth.MTLS.KeyFile)
				if err != nil {
					return conf, fmt.Errorf("load client certificate: %w", err)
				}
			}
			if o.Auth.MTLS.CertData != "" && o.Auth.MTLS.KeyData != "" {
				certData, err := base64.StdEncoding.DecodeString(o.Auth.MTLS.CertData)
				if err != nil {
					return conf, fmt.Errorf("decode client certificate: %w", err)
				}
				keyData, err := base64.StdEncoding.DecodeString(o.Auth.MTLS.KeyData)
				if err != nil {
					return conf, fmt.Errorf("decode client key: %w", err)
				}
				cert, err = tls.X509KeyPair(certData, keyData)
				if err != nil {
					return conf, fmt.Errorf("load client certificate: %w", err)
				}
			}
			tlsconf.Certificates = []tls.Certificate{cert}
		}
		// Append the configuration to the dial options
		conf.Credentials = append(conf.Credentials, grpc.WithTransportCredentials(credentials.NewTLS(&tlsconf)))
	} else {
		log.Warn("Insecure is enabled, not using a TLS transport")
		// Make sure we are using insecure credentials
		conf.Credentials = append(conf.Credentials, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	// Check for per-rpc credentials
	if o.Auth.Basic != (BasicAuthOptions{}) {
		log.Debug("Configuring basic authentication")
		conf.Credentials = append(conf.Credentials, basicauth.NewCreds(o.Auth.Basic.Username, o.Auth.Basic.Password))
	}
	if o.Auth.LDAP != (LDAPAuthOptions{}) {
		log.Debug("Configuring LDAP authentication")
		conf.Credentials = append(conf.Credentials, ldap.NewCreds(o.Auth.LDAP.Username, o.Auth.LDAP.Password))
	}
	return
}

// LoadKey loads the key from the given configuration.
func (o *Config) LoadKey(ctx context.Context) (crypto.PrivateKey, error) {
	log := context.LoggerFrom(ctx)
	if o.WireGuard.KeyFile == "" {
		// Generate an ephemeral key
		log.Debug("Generating ephemeral WireGuard key")
		return crypto.GenerateKey()
	}
	// Check that the file exists and hasn't expired.
	stat, err := os.Stat(o.WireGuard.KeyFile)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat wireguard key file: %w", err)
	} else if os.IsNotExist(err) {
		// Generate a new key
		log.Info("Generating new WireGuard key and saving to file", slog.String("file", o.WireGuard.KeyFile))
		key, err := crypto.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("generate new key: %w", err)
		}
		encoded, err := key.Encode()
		if err != nil {
			return nil, fmt.Errorf("encode key: %w", err)
		}
		if err := os.WriteFile(o.WireGuard.KeyFile, []byte(encoded), 0600); err != nil {
			return nil, fmt.Errorf("write key file: %w", err)
		}
		return key, nil
	}
	if stat.IsDir() {
		return nil, fmt.Errorf("wireguard key file is a directory")
	}
	// Check if the key is expired
	if stat.ModTime().Add(o.WireGuard.KeyRotationInterval).Before(time.Now()) {
		// Delete the key file if it's older than the key rotation interval.
		log.Info("Removing expired WireGuard key file", slog.String("file", o.WireGuard.KeyFile))
		if err := os.Remove(o.WireGuard.KeyFile); err != nil {
			return nil, fmt.Errorf("remove expired wireguard key file: %w", err)
		}
		// Generate a new key and save it to the file
		log.Info("Generating new WireGuard key and saving to file", slog.String("file", o.WireGuard.KeyFile))
		key, err := crypto.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("generate new key: %w", err)
		}
		encoded, err := key.Encode()
		if err != nil {
			return nil, fmt.Errorf("encode key: %w", err)
		}
		if err := os.WriteFile(o.WireGuard.KeyFile, []byte(encoded), 0600); err != nil {
			return nil, fmt.Errorf("write key file: %w", err)
		}
		return key, nil
	}
	// Load the key from the file
	log.Info("Loading WireGuard key from file", slog.String("file", o.WireGuard.KeyFile))
	keyData, err := os.ReadFile(o.WireGuard.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	return crypto.DecodePrivateKey(strings.TrimSpace(string(keyData)))
}

// NewConnectOptions returns new connection options for the configuration. The given raft node must
// be started it can be used. Host can be nil and if one is needed it will be created.
func (o *Config) NewConnectOptions(ctx context.Context, conn mesh.Mesh, raft raft.Raft, host host.Host) (opts mesh.ConnectOptions, err error) {
	// Determine our node ID
	nodeid, err := o.NodeID()
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
	var bootstrap *mesh.BootstrapOptions
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
		for _, id := range o.Bootstrap.Transport.RendezvousNodes {
			if id == nodeid {
				continue
			}
			bootstrapServers = append(bootstrapServers, id)
		}
		bootstrap = &mesh.BootstrapOptions{
			Transport:            rt,
			IPv4Network:          o.Bootstrap.IPv4Network,
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
	plugins, err := o.NewPluginSet(ctx)
	if err != nil {
		return
	}

	var localDNSAddr netip.AddrPort
	if o.Services.MeshDNS.Enabled {
		localDNSAddr, err = netip.ParseAddrPort(o.Services.MeshDNS.ListenUDP)
		if err != nil {
			return
		}
		localDNSAddr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), localDNSAddr.Port())
	}

	opts = mesh.ConnectOptions{
		Raft:                 raft,
		JoinRoundTripper:     joinRT,
		Features:             o.NewFeatureSet(),
		Bootstrap:            bootstrap,
		MaxJoinRetries:       o.Mesh.MaxJoinRetries,
		GRPCAdvertisePort:    o.Mesh.GRPCAdvertisePort,
		MeshDNSAdvertisePort: o.Mesh.MeshDNSAdvertisePort,
		PrimaryEndpoint:      primaryEndpoint,
		WireGuardEndpoints:   wireguardEndpoints,
		RequestVote:          o.Raft.RequestVote,
		RequestObserver:      o.Raft.RequestObserver,
		Routes:               routes,
		DirectPeers: func() map[string]v1.ConnectProtocol {
			peers := make(map[string]v1.ConnectProtocol)
			for _, peer := range o.Mesh.ICEPeers {
				p := peer
				peers[p] = v1.ConnectProtocol_CONNECT_ICE
			}
			for _, peer := range o.Mesh.LibP2PPeers {
				p := peer
				peers[p] = v1.ConnectProtocol_CONNECT_LIBP2P
			}
			return peers
		}(),
		PreferIPv6: o.Raft.PreferIPv6,
		Plugins:    plugins,
		Discovery: func() *libp2p.AnnounceOptions {
			if !o.Discovery.Announce {
				return nil
			}
			return &libp2p.AnnounceOptions{
				Host:        host,
				Rendezvous:  o.Discovery.PSK,
				AnnounceTTL: o.Discovery.AnnounceTTL,
				HostOptions: o.Discovery.HostOptions(ctx, conn.Key()),
			}
		}(),
		NetworkOptions: meshnet.Options{
			NodeID:                nodeid,
			InterfaceName:         o.WireGuard.InterfaceName,
			ForceReplace:          o.WireGuard.ForceInterfaceName,
			ListenPort:            o.WireGuard.ListenPort,
			PersistentKeepAlive:   o.WireGuard.PersistentKeepAlive,
			ForceTUN:              o.WireGuard.ForceTUN,
			MTU:                   o.WireGuard.MTU,
			RecordMetrics:         o.WireGuard.RecordMetrics,
			RecordMetricsInterval: o.WireGuard.RecordMetricsInterval,
			RaftPort:              o.RaftListenPort(),
			GRPCPort:              o.Mesh.GRPCAdvertisePort,
			ZoneAwarenessID:       o.Mesh.ZoneAwarenessID,
			DialOptions:           conn.Credentials(),
			LocalDNSAddr:          localDNSAddr,
			DisableIPv4:           o.Mesh.DisableIPv4,
			DisableIPv6:           o.Mesh.DisableIPv6,
			Relays: meshnet.RelayOptions{
				Host: o.Discovery.HostOptions(ctx, conn.Key()),
			},
		},
	}
	return
}

func (o *Config) NewJoinTransport(ctx context.Context, nodeID string, conn mesh.Mesh, host host.Host) (transport.JoinRoundTripper, error) {
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
	if o.Mesh.JoinAddress != "" {
		return tcp.NewJoinRoundTripper(tcp.RoundTripOptions{
			Addrs:          []string{o.Mesh.JoinAddress},
			Credentials:    conn.Credentials(),
			AddressTimeout: time.Second * 3,
		}), nil
	}
	if o.Discovery.Discover {
		var addrs []multiaddr.Multiaddr
		for _, addr := range o.Discovery.BootstrapServers {
			maddr, err := multiaddr.NewMultiaddr(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid bootstrap peer address: %w", err)
			}
			addrs = append(addrs, maddr)
		}
		joinTransport, err := libp2p.NewJoinRoundTripper(ctx, libp2p.RoundTripOptions{
			Rendezvous: o.Discovery.PSK,
			Host:       host,
			HostOptions: libp2p.HostOptions{
				Key:            conn.Key(),
				BootstrapPeers: addrs,
				ConnectTimeout: o.Discovery.ConnectTimeout,
			},
		})
		if err != nil {
			return nil, fmt.Errorf("create libp2p join transport: %w", err)
		}
		return joinTransport, nil
	}
	// A nil transport is technically okay, it means we are a single-node mesh
	return nil, nil
}
