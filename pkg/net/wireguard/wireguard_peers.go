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
	"net"
	"net/netip"
	"time"

	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/webmeshproj/node/pkg/net/system"
)

// Peer contains configurations for a wireguard peer. When removing,
// only the PublicKey is required.
type Peer struct {
	// ID is the ID of the peer.
	ID string `json:"id"`
	// PublicKey is the public key of the peer.
	PublicKey wgtypes.Key `json:"publicKey"`
	// Endpoint is the endpoint of this peer, if applicable.
	Endpoint netip.AddrPort `json:"endpoint"`
	// AllowedIPs is the list of allowed IPs for this peer.
	AllowedIPs []netip.Prefix `json:"allowedIPs"`
	// AllowedRoutes is the list of allowed routes for this peer.
	AllowedRoutes []netip.Prefix `json:"allowedRoutes"`
}

func (p Peer) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"id":         p.ID,
		"publicKey":  p.PublicKey.String(),
		"endpoint":   p.Endpoint.String(),
		"allowedIPs": p.AllowedIPs,
	})
}

// PutPeer updates a peer in the wireguard configuration.
func (w *wginterface) PutPeer(ctx context.Context, peer *Peer) error {
	w.log.Debug("put peer", slog.Any("peer", peer))
	// Check if we already have the peer under a different key
	// and remove it if so.
	if peerKey, ok := w.peerKeyByID(peer.ID); ok {
		if peerKey.String() != peer.PublicKey.String() {
			// Remove the peer first
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
		if ip.Addr().Is4() {
			ipnet = net.IPNet{
				IP:   ip.Addr().AsSlice(),
				Mask: net.CIDRMask(ip.Bits(), 32),
			}
		} else {
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
		if ip.Addr().Is4() {
			ipnet = net.IPNet{
				IP:   ip.Addr().AsSlice(),
				Mask: net.CIDRMask(ip.Bits(), 32),
			}
		} else {
			ipnet = net.IPNet{
				IP:   ip.Addr().AsSlice(),
				Mask: net.CIDRMask(ip.Bits(), 128),
			}
		}
		allowedRoutes = append(allowedRoutes, ipnet)
	}
	peerCfg := wgtypes.PeerConfig{
		PublicKey:                   peer.PublicKey,
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
	w.log.Debug("configuring device with peer",
		slog.Any("peer", &peerConfigMarshaler{peerCfg}))
	err = w.cli.ConfigureDevice(w.Name(), wgtypes.Config{
		Peers:        []wgtypes.PeerConfig{peerCfg},
		ReplacePeers: false,
	})
	if err != nil {
		return err
	}
	w.registerPeer(peerCfg.PublicKey, peer)
	// Add routes to the allowed IPs
	for _, ip := range allowedIPs {
		addr, _ := netip.AddrFromSlice(ip.IP)
		ones, _ := ip.Mask.Size()
		prefix := netip.PrefixFrom(addr, ones)
		if prefix.Addr().Is6() && w.opts.AddressV6.IsValid() {
			if w.opts.AddressV6.Contains(addr) {
				// Don't readd routes to our own network
				continue
			}
			w.log.Debug("adding ipv6 route", slog.Any("prefix", prefix))
			err = w.AddRoute(ctx, prefix)
			if err != nil && !system.IsRouteExists(err) {
				return fmt.Errorf("failed to add route: %w", err)
			}
		}
		if prefix.Addr().Is4() && w.opts.AddressV4.IsValid() {
			w.log.Debug("adding ipv4 route", slog.Any("prefix", prefix))
			err = w.AddRoute(ctx, prefix)
			if err != nil && !system.IsRouteExists(err) {
				return fmt.Errorf("failed to add route: %w", err)
			}
		}
	}
	return nil
}

// DeletePeer removes a peer from the wireguard configuration.
func (w *wginterface) DeletePeer(ctx context.Context, id string) error {
	if key, ok := w.popPeerKey(id); ok {
		return w.cli.ConfigureDevice(w.Name(), wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey: key,
					Remove:    true,
				},
			},
		})
	}
	return nil
}

// registerPeer adds a peer to the peer map.
func (w *wginterface) registerPeer(key wgtypes.Key, peer *Peer) {
	w.peersMux.Lock()
	defer w.peersMux.Unlock()
	w.peers[peer.ID] = key
}

// popPeerKey removes a peer from the peer map and returns the key.
func (w *wginterface) popPeerKey(id string) (wgtypes.Key, bool) {
	w.peersMux.Lock()
	defer w.peersMux.Unlock()
	for id, k := range w.peers {
		delete(w.peers, id)
		return k, true
	}
	return wgtypes.Key{}, false
}

// peerByPublicKey returns the peer with the given public key.
func (w *wginterface) peerByPublicKey(lookup string) (string, bool) {
	w.peersMux.Lock()
	defer w.peersMux.Unlock()
	for peerID, key := range w.peers {
		if key.String() == lookup {
			return peerID, true
		}
	}
	return "", false
}

// peerKeyByID returns the public key of the peer with the given id.
func (w *wginterface) peerKeyByID(id string) (wgtypes.Key, bool) {
	w.peersMux.Lock()
	defer w.peersMux.Unlock()
	key, ok := w.peers[id]
	return key, ok
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
