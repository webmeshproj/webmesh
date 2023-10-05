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

package meshnet

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/common"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system/dns"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system/firewall"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport/libp2p"
	"github.com/webmeshproj/webmesh/pkg/meshnet/wireguard"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// Options are the options for the network manager.
type Options struct {
	// NetNs is the network namespace to use for the wireguard interface.
	// This is only used on Linux.
	NetNs string
	// InterfaceName is the name of the wireguard interface.
	InterfaceName string
	// ForceReplace is whether to force replace the wireguard interface.
	ForceReplace bool
	// ListenPort is the port to use for wireguard.
	ListenPort int
	// Modprobe is whether to attempt to load the wireguard kernel module.
	Modprobe bool
	// PersistentKeepAlive is the persistent keepalive to use for wireguard.
	PersistentKeepAlive time.Duration
	// ForceTUN is whether to force the use of TUN.
	ForceTUN bool
	// MTU is the MTU to use for the wireguard interface.
	MTU int
	// RecordMetrics is whether to enable metrics recording.
	RecordMetrics bool
	// RecordMetricsInterval is the interval to use for recording metrics.
	RecordMetricsInterval time.Duration
	// StoragePort is the port being used for the storage provider.
	StoragePort int
	// GRPCPort is the port being used for gRPC.
	GRPCPort int
	// ZoneAwarenessID is the zone awareness ID.
	ZoneAwarenessID string
	// DialOptions are the dial options to use when calling peer nodes.
	DialOptions []grpc.DialOption
	// LocalDNSAddr is a local network address service MeshDNS.
	LocalDNSAddr netip.AddrPort
	// DisableIPv4 disables IPv4 on the interface.
	DisableIPv4 bool
	// DisableIPv6 disables IPv6 on the interface.
	DisableIPv6 bool
	// Relays are options for when presented with the need to negotiate
	// p2p data channels.
	Relays RelayOptions
}

func (o *Options) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"netNs":                 o.NetNs,
		"interfaceName":         o.InterfaceName,
		"forceReplace":          o.ForceReplace,
		"listenPort":            o.ListenPort,
		"modprobe":              o.Modprobe,
		"persistentKeepAlive":   o.PersistentKeepAlive,
		"forceTUN":              o.ForceTUN,
		"mtu":                   o.MTU,
		"recordMetrics":         o.RecordMetrics,
		"recordMetricsInterval": o.RecordMetricsInterval,
		"storagePort":           o.StoragePort,
		"grpcPort":              o.GRPCPort,
		"zoneAwarenessID":       o.ZoneAwarenessID,
		"localDNSAddr":          o.LocalDNSAddr,
		"disableIPv4":           o.DisableIPv4,
		"disableIPv6":           o.DisableIPv6,
		"relays":                o.Relays,
	})
}

// RelayOptions are options for when presented with the need to negotiate
// p2p wireguard connections. Empty values mean to use the defaults.
type RelayOptions struct {
	// Host are the options for a libp2p host.
	Host libp2p.HostOptions
}

// StartOptions are the options for starting the network manager and configuring
// the wireguard interface.
type StartOptions struct {
	// Key is the wireguard key to use for the node.
	Key crypto.PrivateKey
	// AddressV4 is the IPv4 address to use for the node.
	AddressV4 netip.Prefix
	// AddressV6 is the IPv6 address to use for the node.
	AddressV6 netip.Prefix
	// NetworkV4 is the IPv4 network to use for the node.
	NetworkV4 netip.Prefix
	// NetworkV6 is the IPv6 network to use for the node.
	NetworkV6 netip.Prefix
}

// Manager is the interface for managing the network.
type Manager interface {
	transport.Dialer

	// Start starts the network manager.
	Start(ctx context.Context, opts StartOptions) error
	// InNetwork returns true if the given address is in the network of this interface.
	InNetwork(addr netip.Addr) bool
	// NetworkV4 returns the current IPv4 network. The returned value may be invalid.
	NetworkV4() netip.Prefix
	// NetworkV6 returns the current IPv6 network, even if it is disabled.
	NetworkV6() netip.Prefix
	// StartMasquerade ensures that masquerading is enabled.
	StartMasquerade(ctx context.Context) error
	// DNS returns the DNS server manager. The DNS server manager is only
	// available after Start has been called.
	DNS() DNSManager
	// Peers return the peer manager.
	Peers() PeerManager
	// Firewall returns the firewall.
	// The firewall is only available after Start has been called.
	Firewall() firewall.Firewall
	// WireGuard returns the wireguard interface.
	// The wireguard interface is only available after Start has been called.
	WireGuard() wireguard.Interface
	// Close closes the network manager and cleans up any resources.
	Close(ctx context.Context) error
}

// New creates a new network manager.
func New(store storage.MeshDB, opts Options, nodeID types.NodeID) Manager {
	m := &manager{
		nodeID:  nodeID,
		storage: store,
		opts:    opts,
	}
	m.peers = newPeerManager(m)
	return m
}

type manager struct {
	opts                 Options
	nodeID               types.NodeID
	key                  crypto.PrivateKey
	peers                *peerManager
	dns                  *dnsManager
	storage              storage.MeshDB
	fw                   firewall.Firewall
	wg                   wireguard.Interface
	networkv4, networkv6 netip.Prefix
	masquerading         bool
	mu                   sync.Mutex
}

func (m *manager) DNS() DNSManager {
	return m.dns
}

func (m *manager) Peers() PeerManager {
	return m.peers
}

func (m *manager) NetworkV4() netip.Prefix {
	return m.networkv4
}

func (m *manager) NetworkV6() netip.Prefix {
	return m.networkv6
}

// InNetwork returns true if the given address is in the network of this interface.
func (w *manager) InNetwork(addr netip.Addr) bool {
	return w.NetworkV4().Contains(addr) || w.NetworkV6().Contains(addr)
}

func (m *manager) Firewall() firewall.Firewall {
	return m.fw
}

func (m *manager) WireGuard() wireguard.Interface {
	return m.wg
}

func (m *manager) Start(ctx context.Context, opts StartOptions) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.key = opts.Key
	log := context.LoggerFrom(ctx).With("component", "net-manager")
	log.Info("Starting mesh network manager")
	if m.opts.Modprobe && runtime.GOOS == "linux" {
		log.Debug("Attempting to load wireguard kernel module")
		err := common.Exec(ctx, "modprobe", "wireguard")
		if err != nil {
			log.Warn("Failed to load wireguard kernel module", slog.String("error", err.Error()))
		}
	}
	log.Debug("Network manager start options", slog.Any("start-opts", opts))
	handleErr := func(err error) error {
		if m.wg != nil {
			if closeErr := m.wg.Close(ctx); closeErr != nil {
				err = fmt.Errorf("%w: %v", err, closeErr)
			}
		}
		if m.fw != nil {
			if clearErr := m.fw.Clear(ctx); clearErr != nil {
				err = fmt.Errorf("%w: %v", err, clearErr)
			}
		}
		return err
	}
	fwopts := &firewall.Options{
		ID:    m.nodeID.String(),
		NetNs: m.opts.NetNs,
		// TODO: Make this configurable
		DefaultPolicy: firewall.PolicyAccept,
		WireguardPort: uint16(m.opts.ListenPort),
		StoragePort:   uint16(m.opts.StoragePort),
		GRPCPort:      uint16(m.opts.GRPCPort),
	}
	log.Debug("Configuring firewall", slog.Any("opts", fwopts))
	var err error
	m.fw, err = firewall.New(ctx, fwopts)
	if err != nil {
		return fmt.Errorf("new firewall manager: %w", err)
	}
	wgopts := &wireguard.Options{
		NetNs:               m.opts.NetNs,
		NodeID:              m.nodeID,
		ListenPort:          m.opts.ListenPort,
		Name:                m.opts.InterfaceName,
		ForceName:           m.opts.ForceReplace,
		ForceTUN:            m.opts.ForceTUN,
		PersistentKeepAlive: m.opts.PersistentKeepAlive,
		MTU:                 m.opts.MTU,
		Metrics:             m.opts.RecordMetrics,
		MetricsInterval:     m.opts.RecordMetricsInterval,
		AddressV4:           opts.AddressV4,
		AddressV6:           opts.AddressV6,
		NetworkV4:           opts.NetworkV4,
		NetworkV6:           opts.NetworkV6,
		DisableIPv4:         m.opts.DisableIPv4,
		DisableIPv6:         m.opts.DisableIPv6,
	}
	log.Debug("Configuring wireguard", slog.Any("opts", wgopts))
	m.wg, err = wireguard.New(ctx, wgopts)
	if err != nil {
		return handleErr(fmt.Errorf("new wireguard interface: %w", err))
	}
	m.dns = &dnsManager{
		wg:           m.wg,
		storage:      m.storage,
		localdnsaddr: m.opts.LocalDNSAddr,
		dnsservers:   []netip.AddrPort{},
		noIPv4:       m.opts.DisableIPv4,
		noIPv6:       m.opts.DisableIPv6,
	}
	err = m.wg.Configure(ctx, opts.Key)
	if err != nil {
		return handleErr(fmt.Errorf("configure wireguard: %w", err))
	}
	if opts.NetworkV6.IsValid() && !m.opts.DisableIPv6 {
		m.networkv6 = opts.NetworkV6
		log.Debug("Adding IPv6 network route", slog.String("network", opts.NetworkV6.String()))
		err = m.wg.AddRoute(ctx, opts.NetworkV6)
		if err != nil && !system.IsRouteExists(err) {
			return handleErr(fmt.Errorf("wireguard add mesh network route: %w", err))
		}
	}
	if opts.AddressV6.IsValid() && !m.opts.DisableIPv6 {
		log.Debug("Adding IPv6 address route", slog.String("address", opts.AddressV6.String()))
		err = m.wg.AddRoute(ctx, opts.AddressV6)
		if err != nil && !system.IsRouteExists(err) {
			return handleErr(fmt.Errorf("wireguard add ipv6 route: %w", err))
		}
	}
	if opts.NetworkV4.IsValid() && !m.opts.DisableIPv4 {
		m.networkv4 = opts.NetworkV4
		log.Debug("Adding IPv4 network route", slog.String("network", opts.NetworkV4.String()))
		err = m.wg.AddRoute(ctx, opts.NetworkV4)
		if err != nil && !system.IsRouteExists(err) {
			return handleErr(fmt.Errorf("wireguard add mesh network route: %w", err))
		}
	}
	log.Debug("Configuring forwarding on wireguard interface", slog.String("interface", m.wg.Name()))
	err = m.fw.AddWireguardForwarding(ctx, m.wg.Name())
	if err != nil {
		return handleErr(fmt.Errorf("add wireguard forwarding rule: %w", err))
	}
	return nil
}

// Dial behaves like the standard library DialContext, but uses the
// wireguard interface for all connections. The address can be a nodeID
// or a network address.
func (m *manager) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.WireGuard() == nil {
		return nil, fmt.Errorf("wireguard interface is not available")
	}
	res := m.dns.Resolver()
	dialer := &net.Dialer{
		Resolver: res,
	}
	// If the address is a node ID, we'll use storage to lookup it's address
	// and dial that instead.
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("split host port: %w", err)
	}
	// This is a bit of a hack, but for now we'll check if its a single word
	// and not an IP address.
	if net.ParseIP(host) == nil && len(strings.Split(host, ".")) == 1 {
		// We'll assume it's a node ID
		currentPeers := m.wg.Peers()
		// Check if we have them registered already locally
		if peerInfo, ok := currentPeers[host]; ok {
			if network == "tcp4" || network == "udp4" || m.opts.DisableIPv6 {
				address = net.JoinHostPort(peerInfo.PrivateIPv4.Addr().String(), port)
			} else {
				address = net.JoinHostPort(peerInfo.PrivateIPv6.Addr().String(), port)
			}
		} else {
			// We gotta hit the database
			peer, err := m.storage.Peers().Get(ctx, types.NodeID(host))
			if err != nil {
				return nil, fmt.Errorf("get peer: %w", err)
			}
			// If it's a v4 network use the peer's v4 address
			if network == "tcp4" || network == "udp4" || m.opts.DisableIPv6 {
				if !peer.PrivateAddrV4().IsValid() {
					// We don't have a v4 address for this peer
					return nil, fmt.Errorf("peer %s does not have a valid v4 address", host)
				}
				address = net.JoinHostPort(peer.PrivateAddrV4().Addr().String(), port)
			} else {
				address = net.JoinHostPort(peer.PrivateAddrV6().Addr().String(), port)
			}
		}
	}
	return dialer.DialContext(ctx, network, address)
}

func (m *manager) StartMasquerade(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.masquerading {
		return nil
	}
	err := m.fw.AddMasquerade(ctx, m.wg.Name())
	if err != nil {
		return fmt.Errorf("add masquerade rule: %w", err)
	}
	m.masquerading = true
	return nil
}

func (m *manager) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	log := context.LoggerFrom(ctx).With("component", "net-manager")
	defer m.peers.Close(context.WithLogger(ctx, log))
	if m.fw != nil {
		// Clear the firewall rules after wireguard is shutdown
		defer func() {
			log.Debug("clearing firewall rules")
			if err := m.fw.Clear(ctx); err != nil {
				log.Error("error clearing firewall rules", slog.String("error", err.Error()))
			}
		}()
	}
	if m.dns != nil {
		if len(m.dns.dnsservers) > 0 {
			log.Debug("removing DNS servers", slog.Any("servers", m.dns.dnsservers))
			err := dns.RemoveServers(m.wg.Name(), m.dns.dnsservers)
			if err != nil {
				log.Error("error removing DNS servers", slog.String("error", err.Error()))
			}
		}
	}
	if m.wg != nil {
		log.Debug("closing wireguard interface")
		err := m.wg.Close(ctx)
		if err != nil {
			return fmt.Errorf("close wireguard: %w", err)
		}
	}
	return nil
}
