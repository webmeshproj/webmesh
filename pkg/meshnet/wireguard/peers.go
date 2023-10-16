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

package wireguard

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"time"

	"github.com/multiformats/go-multiaddr"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system/routes"
)

// Peer contains configurations for a wireguard peer. When removing,
// only the PublicKey is required.
type Peer struct {
	// ID is the ID of the peer.
	ID string `json:"id"`
	// GRPCPort is the gRPC port of the peer.
	GRPCPort int `json:"grpcPort"`
	// StorageProvider indicates if the peer is a able to provide storage.
	StorageProvider bool `json:"storageProvider"`
	// PublicKey is the public key of the peer.
	PublicKey crypto.PublicKey `json:"publicKey"`
	// Multiaddrs is the list of multiaddrs for this peer.
	Multiaddrs []multiaddr.Multiaddr `json:"multiaddrs"`
	// Endpoint is the endpoint of this peer, if applicable.
	Endpoint netip.AddrPort `json:"endpoint"`
	// PrivateIPv4 is the private IPv4 address of this peer, if applicable.
	PrivateIPv4 netip.Prefix `json:"privateIPv4"`
	// PrivateIPv6 is the private IPv6 address of this peer, if applicable.
	PrivateIPv6 netip.Prefix `json:"privateIPv6"`
	// AllowedIPs is the list of allowed IPs for this peer.
	AllowedIPs []netip.Prefix `json:"allowedIPs"`
	// AllowedRoutes is the list of allowed routes for this peer.
	AllowedRoutes []netip.Prefix `json:"allowedRoutes"`
}

func (p Peer) MarshalJSON() ([]byte, error) {
	encoded, err := p.PublicKey.Encode()
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id":         p.ID,
		"publicKey":  encoded,
		"endpoint":   p.Endpoint.String(),
		"allowedIPs": p.AllowedIPs,
		"allowedRoutes": func() []string {
			var routes []string
			for _, route := range p.AllowedRoutes {
				if route.IsValid() {
					routes = append(routes, route.String())
				}
			}
			return routes
		}(),
	})
}

// PutPeer updates a peer in the wireguard configuration.
func (w *wginterface) PutPeer(ctx context.Context, peer *Peer) error {
	w.log.Debug("Ensuring peer in WireGuard interface", slog.Any("peer", peer))
	// Check if we already have the peer under a different key
	// and remove it if so.
	if peerKey, ok := w.peerKeyByID(peer.ID); ok {
		if peerKey.WireGuardKey().String() != peer.PublicKey.WireGuardKey().String() {
			// Remove the peer first
			w.log.Warn("Removing peer with same ID and different public key", slog.String("id", peer.ID))
			if err := w.DeletePeer(ctx, peer.ID); err != nil {
				return fmt.Errorf("remove peer: %w", err)
			}
		}
	}
	var keepAlive *time.Duration
	var allowedIPs []net.IPNet
	if w.opts.PersistentKeepAlive != 0 {
		keepAlive = &w.opts.PersistentKeepAlive
	} else {
		dur := time.Second * 30
		keepAlive = &dur
	}
	for _, ip := range peer.AllowedIPs {
		var ipnet net.IPNet
		if ip.Addr().IsUnspecified() && w.opts.DisableFullTunnel {
			continue
		}
		if ip.Addr().Is4() {
			if w.opts.DisableIPv4 {
				continue
			}
			ipnet = net.IPNet{
				IP:   ip.Addr().AsSlice(),
				Mask: net.CIDRMask(ip.Bits(), 32),
			}
		} else {
			if w.opts.DisableIPv6 {
				continue
			}
			ipnet = net.IPNet{
				IP:   ip.Addr().AsSlice(),
				Mask: net.CIDRMask(ip.Bits(), 128),
			}
		}
		allowedIPs = append(allowedIPs, ipnet)
	}
	var allowedRoutes []net.IPNet
	for _, ip := range peer.AllowedRoutes {
		var ipnet net.IPNet
		if ip.Addr().IsUnspecified() && w.opts.DisableFullTunnel {
			continue
		}
		if ip.Addr().Is4() {
			if w.opts.DisableIPv4 {
				continue
			}
			ipnet = net.IPNet{
				IP:   ip.Addr().AsSlice(),
				Mask: net.CIDRMask(ip.Bits(), 32),
			}
		} else {
			if w.opts.DisableIPv6 {
				continue
			}
			ipnet = net.IPNet{
				IP:   ip.Addr().AsSlice(),
				Mask: net.CIDRMask(ip.Bits(), 128),
			}
		}
		allowedRoutes = append(allowedRoutes, ipnet)
	}
	peerCfg := wgtypes.PeerConfig{
		PublicKey:                   peer.PublicKey.WireGuardKey(),
		AllowedIPs:                  append(allowedIPs, allowedRoutes...),
		PersistentKeepaliveInterval: keepAlive,
		ReplaceAllowedIPs:           true,
	}
	var err error
	if peer.Endpoint.IsValid() {
		peerCfg.Endpoint, err = net.ResolveUDPAddr("udp", peer.Endpoint.String())
		if err != nil {
			return fmt.Errorf("failed to resolve endpoint: %w", err)
		}
	}
	w.log.Debug("Configuring device with peer", slog.Any("peer", &peerConfigMarshaler{peerCfg}))
	if runtime.GOOS == "linux" && w.opts.NetNs != "" {
		err = system.DoInNetNS(w.opts.NetNs, func() error {
			return w.putPeer(peerCfg)
		})
		if err != nil {
			return err
		}
	} else {
		err = w.putPeer(peerCfg)
		if err != nil {
			return err
		}
	}
	w.registerPeer(peer)
	// Add routes to the allowed IPs
	for _, ip := range append(allowedIPs, allowedRoutes...) {
		addr, _ := netip.AddrFromSlice(ip.IP)
		ones, _ := ip.Mask.Size()
		prefix := netip.PrefixFrom(addr, ones)
		// Skip adding routes to our own network
		if w.opts.NetworkV4.IsValid() && addr.Is4() && !w.opts.DisableIPv4 {
			if w.opts.NetworkV4.Contains(addr) {
				w.log.Debug("Skipping route to own network", slog.String("prefix", prefix.String()))
				continue
			}
		}
		if w.opts.NetworkV6.IsValid() && addr.Is6() && !w.opts.DisableIPv6 {
			if w.opts.NetworkV6.Contains(addr) {
				w.log.Debug("Skipping route to own network", slog.String("prefix", prefix.String()))
				continue
			}
		}
		// If this is a default IPv4 gateway route set the system default route
		if addr.Is4() && addr.IsUnspecified() && ones == 0 {
			if w.opts.DisableFullTunnel {
				// We shouldn't have gotten here, but just in case
				w.log.Debug("Skipping setting default IPv4 gateway", slog.String("prefix", prefix.String()))
				continue
			}
			if !w.opts.DisableIPv4 && !w.changedGateway {
				w.log.Debug("Setting default IPv4 gateway", slog.String("prefix", prefix.String()))
				var err error
				if w.opts.NetNs != "" {
					err = system.DoInNetNS(w.opts.NetNs, func() error {
						return routes.SetDefaultIPv4Gateway(ctx, routes.Gateway{
							Name: w.Name(),
							Addr: w.AddressV4().Addr(),
						})
					})
				} else {
					err = routes.SetDefaultIPv4Gateway(ctx, routes.Gateway{
						Name: w.Name(),
						Addr: w.AddressV4().Addr(),
					})
				}
				if err != nil {
					return fmt.Errorf("failed to set default IPv4 gateway: %w", err)
				}
				w.changedGateway = true
				continue
			}
		}
		// Add any other routes
		if prefix.Addr().Is4() && !w.opts.DisableIPv4 {
			w.log.Debug("Adding IPv4 route to interface", slog.Any("prefix", prefix))
			err = w.AddRoute(ctx, prefix)
			if err != nil && !system.IsRouteExists(err) {
				return fmt.Errorf("failed to add route: %w", err)
			}
		}
		if prefix.Addr().Is6() && !w.opts.DisableIPv6 {
			if w.opts.AddressV6.Contains(addr) {
				// Don't readd routes to our own network
				continue
			}
			w.log.Debug("Adding IPv6 route to interface", slog.Any("prefix", prefix))
			err = w.AddRoute(ctx, prefix)
			if err != nil && !system.IsRouteExists(err) {
				return fmt.Errorf("failed to add route: %w", err)
			}
		}
	}
	return nil
}

func (w *wginterface) putPeer(cfg wgtypes.PeerConfig) error {
	cli, err := wgctrl.New()
	if err != nil {
		return err
	}
	return cli.ConfigureDevice(w.Name(), wgtypes.Config{
		Peers:        []wgtypes.PeerConfig{cfg},
		ReplacePeers: false,
	})
}

// DeletePeer removes a peer from the wireguard configuration.
func (w *wginterface) DeletePeer(ctx context.Context, id string) error {
	if key, ok := w.popPeerKey(id); ok {
		w.log.Debug("Deleting peer from interface",
			slog.String("id", id),
			slog.String("key", key.WireGuardKey().String()),
		)
		if runtime.GOOS == "linux" && w.opts.NetNs != "" {
			return system.DoInNetNS(w.opts.NetNs, func() error {
				return w.deletePeer(key)
			})
		}
		return w.deletePeer(key)
	}
	return nil
}

func (w *wginterface) deletePeer(key crypto.PublicKey) error {
	cli, err := wgctrl.New()
	if err != nil {
		return err
	}
	return cli.ConfigureDevice(w.Name(), wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: key.WireGuardKey(),
				Remove:    true,
			},
		},
		ReplacePeers: false,
	})
}

// registerPeer adds a peer to the peer map.
func (w *wginterface) registerPeer(peer *Peer) {
	w.peersMux.Lock()
	defer w.peersMux.Unlock()
	w.peers[peer.ID] = *peer
}

// popPeerKey removes a peer from the peer map and returns the key.
func (w *wginterface) popPeerKey(id string) (crypto.PublicKey, bool) {
	w.peersMux.Lock()
	defer w.peersMux.Unlock()
	for peerID, peer := range w.peers {
		if peerID == id {
			delete(w.peers, id)
			return peer.PublicKey, true
		}
	}
	return nil, false
}

// peerByPublicKey returns the peer with the given public key.
func (w *wginterface) peerByPublicKey(lookup crypto.PublicKey) (string, bool) {
	w.peersMux.Lock()
	defer w.peersMux.Unlock()
	for peerID, peer := range w.peers {
		if peer.PublicKey.WireGuardKey().String() == lookup.WireGuardKey().String() {
			return peerID, true
		}
	}
	return "", false
}

// peerKeyByID returns the public key of the peer with the given id.
func (w *wginterface) peerKeyByID(id string) (crypto.PublicKey, bool) {
	w.peersMux.Lock()
	defer w.peersMux.Unlock()
	peer, ok := w.peers[id]
	if !ok {
		return nil, false
	}
	return peer.PublicKey, ok
}

type peerConfigMarshaler struct {
	wgtypes.PeerConfig
}

func (m peerConfigMarshaler) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"public_key":         m.PublicKey.String(),
		"endpoint":           m.Endpoint.String(),
		"keepalive_interval": m.PersistentKeepaliveInterval,
		"allowed_ips": func() []string {
			var ips []string
			for _, ip := range m.AllowedIPs {
				ips = append(ips, ip.String())
			}
			return ips
		}(),
	})
}
