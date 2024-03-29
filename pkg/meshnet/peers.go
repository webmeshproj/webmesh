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

// Package meshnet provides the core networking functionality for WebMesh.
package meshnet

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/multiformats/go-multiaddr"
	v1 "github.com/webmeshproj/api/go/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshnet/endpoints"
	"github.com/webmeshproj/webmesh/pkg/meshnet/netutil"
	"github.com/webmeshproj/webmesh/pkg/meshnet/relay"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport/datachannels"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport/libp2p"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport/tcp"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport/webrtc"
	"github.com/webmeshproj/webmesh/pkg/meshnet/wireguard"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// PeerManager is the interface for tracking and managing WireGuard peers.
type PeerManager interface {
	// AddPeer adds a peer to the wireguard interface. IceServers is optional
	// and provides a hint of mesh nodes that provide WebRTC signaling if
	// required.
	Add(ctx context.Context, peer *v1.WireGuardPeer, iceServers []string) error
	// RefreshPeers walks all peers against the provided list and makes sure
	// they are up to date.
	Refresh(ctx context.Context, peers []*v1.WireGuardPeer) error
	// Sync is like refresh but uses the storage to get the list of peers.
	Sync(ctx context.Context) error
	// Resolver returns a resolver backed by the storage
	// of this instance.
	Resolver() PeerResolver
}

// PeerFilterFunc is a function that can be used to filter responses returned by a resolver.
type PeerFilterFunc func(types.MeshNode) bool

// PeerResolver provides facilities for creating various transport.Resolver instances.
type PeerResolver interface {
	// NodeIDResolver returns a resolver that resolves node addresses by node ID.
	NodeIDResolver() transport.NodeIDResolver
	// FeatureResolver returns a resolver that resolves node addresses by feature.
	FeatureResolver(filterFn ...PeerFilterFunc) transport.FeatureResolver
}

type peerManager struct {
	net      *manager
	storage  storage.MeshDB
	p2pConns map[string]clientPeerConn
	peermu   sync.Mutex
	p2pmu    sync.Mutex
}

func newPeerManager(m *manager) *peerManager {
	return &peerManager{
		net:      m,
		storage:  m.storage,
		p2pConns: make(map[string]clientPeerConn),
	}
}

type clientPeerConn struct {
	peerConn  io.Closer
	localAddr netip.AddrPort
}

func (m *peerManager) Close(ctx context.Context) {
	m.peermu.Lock()
	defer m.peermu.Unlock()
	for _, conn := range m.p2pConns {
		err := conn.peerConn.Close()
		if err != nil {
			context.LoggerFrom(ctx).Error("Error closing peer connection", slog.String("error", err.Error()))
		}
	}
	m.p2pConns = make(map[string]clientPeerConn)
}

func (m *peerManager) Resolver() PeerResolver {
	return NewResolver(m.net.storage)
}

func (m *peerManager) Add(ctx context.Context, peer *v1.WireGuardPeer, iceServers []string) error {
	m.peermu.Lock()
	defer m.peermu.Unlock()
	if m.net.WireGuard() == nil {
		return errors.New("add peer called before wireguard interface is ready")
	}
	log := context.LoggerFrom(ctx).With("component", "net-manager")
	ctx = context.WithLogger(ctx, log)
	return m.addPeer(ctx, peer, iceServers)
}

func (m *peerManager) Sync(ctx context.Context) error {
	peers, err := WireGuardPeersFor(ctx, m.net.storage, m.net.nodeID)
	if err != nil {
		return fmt.Errorf("get wireguard peers: %w", err)
	}
	return m.Refresh(ctx, peers)
}

func (m *peerManager) Refresh(ctx context.Context, wgpeers []*v1.WireGuardPeer) error {
	m.peermu.Lock()
	defer m.peermu.Unlock()
	if m.net.WireGuard() == nil {
		return errors.New("refresh peers called before wireguard interface is ready")
	}
	log := context.LoggerFrom(ctx).With("component", "net-manager")
	ctx = context.WithLogger(ctx, log)
	log.Debug("Current wireguard peers", slog.Any("peers", wgpeers))
	currentPeers := m.net.WireGuard().Peers()
	seenPeers := make(map[string]struct{})
	errs := make([]error, 0)
	for _, peer := range wgpeers {
		seenPeers[peer.GetNode().GetId()] = struct{}{}
		// Ensure the peer is configured
		err := m.addPeer(ctx, peer, nil)
		if err != nil {
			log.Error("Error adding peer", slog.String("error", err.Error()))
			errs = append(errs, fmt.Errorf("add peer: %w", err))
		}
	}
	// Remove any peers that are no longer in the store
	for peer := range currentPeers {
		if _, ok := seenPeers[peer]; !ok {
			log.Debug("Removing peer", slog.String("peer_id", peer))
			m.p2pmu.Lock()
			if conn, ok := m.p2pConns[peer]; ok {
				conn.peerConn.Close()
				delete(m.p2pConns, peer)
			}
			m.p2pmu.Unlock()
			if err := m.net.WireGuard().DeletePeer(ctx, peer); err != nil {
				errs = append(errs, fmt.Errorf("delete peer: %w", err))
			}
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (m *peerManager) addPeer(ctx context.Context, peer *v1.WireGuardPeer, iceServers []string) error {
	log := context.LoggerFrom(ctx)
	key, err := crypto.DecodePublicKey(peer.GetNode().GetPublicKey())
	if err != nil {
		return fmt.Errorf("parse peer key: %w", err)
	}
	var priv4, priv6 netip.Prefix
	if peer.GetNode().GetPrivateIPv4() != "" {
		priv4, err = netip.ParsePrefix(peer.GetNode().GetPrivateIPv4())
		if err != nil {
			return fmt.Errorf("parse peer ipv4: %w", err)
		}
	}
	if peer.GetNode().GetPrivateIPv6() != "" {
		priv6, err = netip.ParsePrefix(peer.GetNode().GetPrivateIPv6())
		if err != nil {
			return fmt.Errorf("parse peer ipv6: %w", err)
		}
	}
	endpoint, err := m.determinePeerEndpoint(ctx, peer, iceServers)
	if err != nil {
		if peer.GetProto() == v1.ConnectProtocol_CONNECT_NATIVE {
			return fmt.Errorf("determine peer endpoint: %w", err)
		}
		// If this is a p2p peer, we'll entertain that they might be able
		// to connect to us.
		log.Warn("Error determining peer endpoint, will wait for incoming connection", "error", err.Error())
	}
	allowedIPs := make([]netip.Prefix, 0)
	for _, ip := range peer.GetAllowedIPs() {
		prefix, err := netip.ParsePrefix(ip)
		if err != nil {
			return fmt.Errorf("parse peer allowed ip: %w", err)
		}
		if m.net.opts.DisableIPv4 && prefix.Addr().Is4() {
			continue
		}
		if m.net.opts.DisableIPv6 && prefix.Addr().Is6() {
			continue
		}
		allowedIPs = append(allowedIPs, prefix)
	}
	allowedRoutes := make([]netip.Prefix, 0)
	for _, ip := range peer.GetAllowedRoutes() {
		prefix, err := netip.ParsePrefix(ip)
		if err != nil {
			return fmt.Errorf("parse peer allowed route: %w", err)
		}
		if m.net.opts.DisableIPv4 && prefix.Addr().Is4() {
			continue
		}
		if m.net.opts.DisableIPv6 && prefix.Addr().Is6() {
			continue
		}
		allowedRoutes = append(allowedRoutes, prefix)
	}
	var rpcPort int
	var isStorageProvider bool
	for _, feat := range peer.GetNode().GetFeatures() {
		if feat.Feature == v1.Feature_STORAGE_PROVIDER {
			// They are a raft member
			isStorageProvider = true
		}
		if feat.Feature == v1.Feature_NODES {
			// This is their RPC port
			rpcPort = int(feat.Port)
		}
	}
	wgpeer := wireguard.Peer{
		ID:              peer.GetNode().GetId(),
		GRPCPort:        rpcPort,
		StorageProvider: isStorageProvider,
		PublicKey:       key,
		Endpoint:        endpoint,
		PrivateIPv4:     priv4,
		PrivateIPv6:     priv6,
		AllowedIPs:      allowedIPs,
		AllowedRoutes:   allowedRoutes,
	}
	for _, addr := range peer.GetNode().GetMultiaddrs() {
		ma, err := multiaddr.NewMultiaddr(addr)
		if err == nil {
			wgpeer.Multiaddrs = append(wgpeer.Multiaddrs, ma)
		}
	}
	log.Debug("Ensuring wireguard peer", slog.Any("peer", &wgpeer))
	err = m.net.WireGuard().PutPeer(ctx, &wgpeer)
	if err != nil {
		return fmt.Errorf("put wireguard peer: %w", err)
	}
	// Try to ping the peer to establish a connection
	go func() {
		// TODO: make this configurable
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var addr netip.Prefix
		var err error
		if !m.net.opts.DisableIPv4 && peer.GetNode().GetPrivateIPv4() != "" {
			addr, err = netip.ParsePrefix(peer.GetNode().GetPrivateIPv4())
		} else {
			addr, err = netip.ParsePrefix(peer.GetNode().GetPrivateIPv6())
		}
		if err != nil {
			log.Warn("Could not parse peer address", slog.String("error", err.Error()))
			return
		}
		err = netutil.Ping(ctx, addr.Addr())
		if err != nil {
			log.Debug("Could not ping descendant", slog.String("descendant", peer.GetNode().GetId()), slog.String("error", err.Error()))
			return
		}
		log.Debug("Successfully pinged descendant", slog.String("descendant", peer.GetNode().GetId()))
	}()
	return nil
}

func (m *peerManager) determinePeerEndpoint(ctx context.Context, peer *v1.WireGuardPeer, iceServers []string) (netip.AddrPort, error) {
	log := context.LoggerFrom(ctx)
	var endpoint netip.AddrPort
	if peer.GetProto() == v1.ConnectProtocol_CONNECT_ICE {
		return m.negotiateICEConn(ctx, peer, iceServers)
	}
	if peer.GetProto() == v1.ConnectProtocol_CONNECT_LIBP2P {
		return m.negotiateP2PRelay(ctx, peer)
	}
	// TODO: We don't honor ipv4/ipv6 preferences currently in this function
	if peer.GetNode().GetPrimaryEndpoint() != "" {
		addr, err := net.ResolveUDPAddr("udp", peer.GetNode().GetPrimaryEndpoint())
		if err != nil {
			return endpoint, fmt.Errorf("resolve primary endpoint: %w", err)
		}
		if addr.AddrPort().Addr().Is4In6() {
			// This is an IPv4 address masquerading as an IPv6 address.
			// We need to convert it to a real IPv4 address.
			// This is a workaround for a bug in Go's net package.
			addr = &net.UDPAddr{
				IP:   addr.IP.To4(),
				Port: addr.Port,
			}
		}
		endpoint = addr.AddrPort()
	}
	// Check if we are using zone awareness and the peer is in the same zone
	if m.net.opts.ZoneAwarenessID != "" && peer.GetNode().GetZoneAwarenessID() == m.net.opts.ZoneAwarenessID {
		log.Debug("Using zone awareness, collecting local CIDRs")
		localCIDRs, err := endpoints.Detect(ctx, endpoints.DetectOpts{
			DetectPrivate:  true,
			DetectIPv6:     true,
			SkipInterfaces: []string{m.net.WireGuard().Name()},
		})
		if err != nil {
			return endpoint, fmt.Errorf("detect local cidrs: %w", err)
		}
		log.Debug("Detected local CIDRs", slog.Any("cidrs", localCIDRs.Strings()))
		// If the primary endpoint is not in our zone and additional endpoints are available,
		// check if any of the additional endpoints are in our zone
		if !localCIDRs.Contains(endpoint.Addr()) && len(peer.GetNode().GetWireguardEndpoints()) > 0 {
			for _, additionalEndpoint := range peer.GetNode().GetWireguardEndpoints() {
				addr, err := net.ResolveUDPAddr("udp", additionalEndpoint)
				if err != nil {
					log.Error("could not resolve peer primary endpoint", slog.String("error", err.Error()))
					continue
				}
				if addr.AddrPort().Addr().Is4In6() {
					// Same as above, this is an IPv4 address masquerading as an IPv6 address.
					addr = &net.UDPAddr{
						IP:   addr.IP.To4(),
						Port: addr.Port,
					}
				}
				log.Debug("Evalauting zone awareness endpoint",
					slog.String("endpoint", addr.String()),
					slog.String("zone", peer.GetNode().GetZoneAwarenessID()))
				ep := addr.AddrPort()
				if localCIDRs.Contains(ep.Addr()) {
					// We found an additional endpoint that is in one of our local
					// CIDRs. We'll use this one instead.
					log.Debug("Zone awareness shared with peer, using LAN endpoint", slog.String("endpoint", ep.String()))
					endpoint = ep
					break
				}
			}
		}
	}
	return endpoint, nil
}

func (m *peerManager) negotiateP2PRelay(ctx context.Context, peer *v1.WireGuardPeer) (netip.AddrPort, error) {
	log := context.LoggerFrom(ctx)
	m.p2pmu.Lock()
	if conn, ok := m.p2pConns[peer.GetNode().GetId()]; ok {
		// We already have an ICE connection for this peer
		log.Debug("Using existing wireguard p2p relay", slog.String("local-proxy", conn.localAddr.String()), slog.String("peer", peer.GetNode().GetId()))
		m.p2pmu.Unlock()
		return conn.localAddr, nil
	}
	m.p2pmu.Unlock()
	wgPort, err := m.net.WireGuard().ListenPort()
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("wireguard listen port: %w", err)
	}
	remotePub, err := crypto.DecodePublicKey(peer.GetNode().GetPublicKey())
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parse peer host key: %w", err)
	}
	relay, err := libp2p.NewUDPRelay(ctx, libp2p.UDPRelayOptions{
		PrivateKey:   m.net.key,
		RemotePubKey: remotePub,
		Relay: relay.UDPOptions{
			TargetPort: uint16(wgPort),
		},
		Host: libp2p.HostOptions{
			BootstrapPeers: m.net.opts.Relays.Host.BootstrapPeers,
			Options:        m.net.opts.Relays.Host.Options,
			LocalAddrs:     m.net.opts.Relays.Host.LocalAddrs,
			ConnectTimeout: m.net.opts.Relays.Host.ConnectTimeout,
		},
	})
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("create udp relay: %w", err)
	}
	go func() {
		<-relay.Closed()
		defer func() {
			// This is a hacky way to attempt to reconnect to the peer if
			// the ICE connection is closed and they are still in the store.
			wgpeers, err := WireGuardPeersFor(ctx, m.net.storage, m.net.nodeID)
			if err != nil {
				log.Error("Error getting wireguard peers after p2p connection closed", slog.String("error", err.Error()))
				return
			}
			if err := m.Refresh(context.Background(), wgpeers); err != nil {
				log.Error("Error refreshing peers after p2p connection closed", slog.String("error", err.Error()))
			}
		}()
		m.p2pmu.Lock()
		delete(m.p2pConns, peer.GetNode().GetId())
		m.p2pmu.Unlock()
	}()
	m.p2pmu.Lock()
	defer m.p2pmu.Unlock()
	peerconn := clientPeerConn{
		peerConn:  relay,
		localAddr: relay.LocalAddr().AddrPort(),
	}
	m.p2pConns[peer.GetNode().GetId()] = peerconn
	return peerconn.localAddr, nil
}

func (m *peerManager) negotiateICEConn(ctx context.Context, peer *v1.WireGuardPeer, iceServers []string) (netip.AddrPort, error) {
	m.p2pmu.Lock()
	log := context.LoggerFrom(ctx)
	if conn, ok := m.p2pConns[peer.GetNode().GetId()]; ok {
		// We already have an ICE connection for this peer
		log.Debug("Using existing wireguard ICE proxy", slog.String("local-proxy", conn.localAddr.String()), slog.String("peer", peer.GetNode().GetId()))
		m.p2pmu.Unlock()
		return conn.localAddr, nil
	}
	m.p2pmu.Unlock()
	wgPort, err := m.net.WireGuard().ListenPort()
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("wireguard listen port: %w", err)
	}
	var endpoint netip.AddrPort
	log.Debug("Negotiating wireguard ICE proxy", slog.String("peer", peer.GetNode().GetId()))
	var tries int
	var maxTries = 5
	var pc *datachannels.WireGuardProxyClient
	for tries < maxTries {
		rt, err := m.getSignalingTransport(ctx, peer, iceServers)
		if err != nil {
			return endpoint, fmt.Errorf("get signaling transport: %w", err)
		}
		pc, err = datachannels.NewWireGuardProxyClient(ctx, rt, uint16(wgPort))
		if err == nil {
			break
		}
		if err != nil {
			tries++
			if tries >= maxTries {
				return endpoint, fmt.Errorf("create wireguard proxy client: %w", err)
			}
			log.Error("Error creating wireguard proxy client, retrying", slog.String("error", err.Error()))
			time.Sleep(time.Second * 2)
		}
	}
	go func() {
		<-pc.Closed()
		defer func() {
			// This is a hacky way to attempt to reconnect to the peer if
			// the ICE connection is closed and they are still in the store.
			wgpeers, err := WireGuardPeersFor(ctx, m.net.storage, m.net.nodeID)
			if err != nil {
				log.Error("Error getting wireguard peers after ICE connection closed", slog.String("error", err.Error()))
				return
			}
			if err := m.Refresh(context.Background(), wgpeers); err != nil {
				log.Error("Error refreshing peers after ICE connection closed", slog.String("error", err.Error()))
			}
		}()
		m.p2pmu.Lock()
		delete(m.p2pConns, peer.GetNode().GetId())
		m.p2pmu.Unlock()
	}()
	m.p2pmu.Lock()
	defer m.p2pmu.Unlock()
	peerconn := clientPeerConn{
		peerConn:  pc,
		localAddr: pc.LocalAddr().AddrPort(),
	}
	m.p2pConns[peer.GetNode().GetId()] = peerconn
	return peerconn.localAddr, nil
}

func (m *peerManager) getSignalingTransport(ctx context.Context, peer *v1.WireGuardPeer, iceServers []string) (transport.WebRTCSignalTransport, error) {
	log := context.LoggerFrom(ctx)
	var resolver transport.FeatureResolver
	if len(iceServers) > 0 {
		// We have a hint about ICE servers, we'll use a static resolver
		log.Debug("We have a hint about ICE servers, we'll use a static resolver", slog.Any("servers", iceServers))
		resolver = transport.FeatureResolverFunc(func(ctx context.Context, lookup v1.Feature) ([]netip.AddrPort, error) {
			var addports []netip.AddrPort
			for _, server := range iceServers {
				addr, err := net.ResolveUDPAddr("udp", server)
				if err != nil {
					return nil, fmt.Errorf("resolve udp addr: %w", err)
				}
				addports = append(addports, addr.AddrPort())
			}
			return addports, nil
		})
	} else {
		// We'll use our local storage
		log.Debug("We'll use our local storage for ICE negotiation lookup")
		resolver = m.Resolver().FeatureResolver(func(mn types.MeshNode) bool {
			return mn.GetId() != peer.GetNode().GetId()
		})
	}
	return webrtc.NewSignalTransport(webrtc.SignalOptions{
		Resolver: resolver,
		Transport: tcp.NewGRPCTransport(tcp.TransportOptions{
			MaxRetries:  5,
			Credentials: m.net.opts.Credentials,
		}),
		NodeID:      peer.GetNode().GetId(),
		TargetProto: "udp",
		TargetAddr:  netip.AddrPortFrom(netip.IPv4Unspecified(), 0),
	}), nil
}
