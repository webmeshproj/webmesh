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

package net

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	"github.com/webmeshproj/webmesh/pkg/net/datachannels"
	"github.com/webmeshproj/webmesh/pkg/net/endpoints"
	"github.com/webmeshproj/webmesh/pkg/net/mesh"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/net/transport/tcp"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
	"github.com/webmeshproj/webmesh/pkg/util/netutil"
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
}

type peerManager struct {
	net      *manager
	iceConns map[string]clientPeerConn
	peermu   sync.Mutex
	pcmu     sync.Mutex
}

func newPeerManager(m *manager) *peerManager {
	return &peerManager{
		net:      m,
		iceConns: make(map[string]clientPeerConn),
	}
}

type clientPeerConn struct {
	peerConn  *datachannels.WireGuardProxyClient
	localAddr netip.AddrPort
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
		seenPeers[peer.GetId()] = struct{}{}
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
			m.pcmu.Lock()
			if conn, ok := m.iceConns[peer]; ok {
				conn.peerConn.Close()
				delete(m.iceConns, peer)
			}
			m.pcmu.Unlock()
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
	key, err := wgtypes.ParseKey(peer.GetPublicKey())
	if err != nil {
		return fmt.Errorf("parse peer key: %w", err)
	}
	var priv4, priv6 netip.Prefix
	if peer.AddressIpv4 != "" {
		priv4, err = netip.ParsePrefix(peer.AddressIpv4)
		if err != nil {
			return fmt.Errorf("parse peer ipv4: %w", err)
		}
	}
	if peer.AddressIpv6 != "" {
		priv6, err = netip.ParsePrefix(peer.AddressIpv6)
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
	for _, ip := range peer.GetAllowedIps() {
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
	var isRaftMember bool
	for _, feat := range peer.GetFeatures() {
		if feat.Feature == v1.Feature_STORAGE {
			// They are a raft member
			isRaftMember = true
		}
		if feat.Feature == v1.Feature_NODES {
			// This is their RPC port
			rpcPort = int(feat.Port)
		}
	}
	wgpeer := wireguard.Peer{
		ID:            peer.GetId(),
		GRPCPort:      rpcPort,
		RaftMember:    isRaftMember,
		PublicKey:     key,
		Endpoint:      endpoint,
		PrivateIPv4:   priv4,
		PrivateIPv6:   priv6,
		AllowedIPs:    allowedIPs,
		AllowedRoutes: allowedRoutes,
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
		if !m.net.opts.DisableIPv4 && peer.AddressIpv4 != "" {
			addr, err = netip.ParsePrefix(peer.AddressIpv4)
		} else {
			addr, err = netip.ParsePrefix(peer.AddressIpv6)
		}
		if err != nil {
			log.Warn("Could not parse peer address", slog.String("error", err.Error()))
			return
		}
		err = netutil.Ping(ctx, addr.Addr())
		if err != nil {
			log.Debug("Could not ping descendant", slog.String("descendant", peer.Id), slog.String("error", err.Error()))
			return
		}
		log.Debug("Successfully pinged descendant", slog.String("descendant", peer.Id))
	}()
	return nil
}

func (m *peerManager) determinePeerEndpoint(ctx context.Context, peer *v1.WireGuardPeer, iceServers []string) (netip.AddrPort, error) {
	log := context.LoggerFrom(ctx)
	var endpoint netip.AddrPort
	if peer.GetProto() == v1.ConnectProtocol_CONNECT_ICE {
		// Setup an ICE relay
		return m.negotiateICEConn(ctx, peer, iceServers)
	}
	if peer.GetProto() == v1.ConnectProtocol_CONNECT_LIBP2P {
		// Make sure we have a rendevous string for them
		if _, ok := m.net.opts.Relays.RendezvousStrings[peer.GetId()]; !ok {
			return endpoint, fmt.Errorf("no rendezvous string for peer %s", peer.GetId())
		}
		// TODO: Set up a libp2p relay
	}
	// TODO: We don't honor ipv4/ipv6 preferences currently in this function
	if peer.GetPrimaryEndpoint() != "" {
		addr, err := net.ResolveUDPAddr("udp", peer.GetPrimaryEndpoint())
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
	if m.net.opts.ZoneAwarenessID != "" && peer.GetZoneAwarenessId() == m.net.opts.ZoneAwarenessID {
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
		if !localCIDRs.Contains(endpoint.Addr()) && len(peer.GetWireguardEndpoints()) > 0 {
			for _, additionalEndpoint := range peer.GetWireguardEndpoints() {
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
					slog.String("zone", peer.GetZoneAwarenessId()))
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

func (m *peerManager) negotiateICEConn(ctx context.Context, peer *v1.WireGuardPeer, iceServers []string) (netip.AddrPort, error) {
	m.pcmu.Lock()
	defer m.pcmu.Unlock()
	log := context.LoggerFrom(ctx)
	if conn, ok := m.iceConns[peer.GetId()]; ok {
		// We already have an ICE connection for this peer
		log.Debug("Using existing wireguard ICE proxy", slog.String("local-proxy", conn.localAddr.String()), slog.String("peer", peer.GetId()))
		return conn.localAddr, nil
	}
	wgPort, err := m.net.WireGuard().ListenPort()
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("wireguard listen port: %w", err)
	}
	var endpoint netip.AddrPort
	log.Debug("Negotiating wireguard ICE proxy", slog.String("peer", peer.GetId()))
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
			wgpeers, err := mesh.WireGuardPeersFor(ctx, m.net.storage, m.net.opts.NodeID)
			if err != nil {
				log.Error("Error getting wireguard peers after ICE connection closed", slog.String("error", err.Error()))
				return
			}
			if err := m.Refresh(context.Background(), wgpeers); err != nil {
				log.Error("Error refreshing peers after ICE connection closed", slog.String("error", err.Error()))
			}
		}()
		m.pcmu.Lock()
		delete(m.iceConns, peer.GetId())
		m.pcmu.Unlock()
	}()
	peerconn := clientPeerConn{
		peerConn:  pc,
		localAddr: pc.LocalAddr().AddrPort(),
	}
	m.iceConns[peer.GetId()] = peerconn
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
		resolver = peers.New(m.net.storage).Resolver().FeatureResolver(func(mn peers.MeshNode) bool {
			return mn.GetId() != peer.GetId()
		})
	}
	return tcp.NewSignalTransport(tcp.WebRTCSignalOptions{
		Resolver:    resolver,
		Credentials: m.net.opts.DialOptions,
		NodeID:      peer.GetId(),
		TargetProto: "udp",
		TargetAddr:  netip.AddrPortFrom(netip.IPv4Unspecified(), 0),
	}), nil
}
