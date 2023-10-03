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

package testutil

import (
	"context"
	"net/netip"
	"sync"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system"
	"github.com/webmeshproj/webmesh/pkg/meshnet/wireguard"
)

// WireGuardInterface is a test interface for use with testing.
// It implements wireguard.Interface but maintains state in-memory
// and does not make any modifications to the system.
type WireGuardInterface struct {
	system.Interface
	opts  *wireguard.Options
	key   crypto.PrivateKey
	peers map[string]wireguard.Peer
	mu    sync.Mutex
}

// NewWireGuardInterface creates a new test wireguard interface.
func NewWireGuardInterface(ctx context.Context, opts *wireguard.Options) (wireguard.Interface, error) {
	systemInterface, err := NewSystemInterface(ctx, &system.Options{
		Name:        opts.Name,
		AddressV4:   opts.AddressV4,
		AddressV6:   opts.AddressV6,
		ForceTUN:    opts.ForceTUN,
		MTU:         uint32(opts.MTU),
		DisableIPv4: opts.DisableIPv4,
		DisableIPv6: opts.DisableIPv6,
	})
	if err != nil {
		return nil, err
	}
	return &WireGuardInterface{
		Interface: systemInterface,
		opts:      opts,
	}, nil
}

// NetworkV4 returns the IPv4 network of this interface.
func (wg *WireGuardInterface) NetworkV4() netip.Prefix {
	return wg.opts.AddressV4
}

// NetworkV6 returns the IPv6 network of this interface.
func (wg *WireGuardInterface) NetworkV6() netip.Prefix {
	return wg.opts.AddressV6
}

// InNetwork returns true if the given address is in the network of this interface.
func (wg *WireGuardInterface) InNetwork(addr netip.Addr) bool {
	if wg.opts.NetworkV4.IsValid() && wg.opts.NetworkV4.Contains(addr) {
		return true
	}
	if wg.opts.NetworkV6.IsValid() && wg.opts.NetworkV6.Contains(addr) {
		return true
	}
	return false
}

// Configure configures the wireguard interface to use the given key and listen port.
func (wg *WireGuardInterface) Configure(ctx context.Context, key crypto.PrivateKey) error {
	wg.mu.Lock()
	defer wg.mu.Unlock()
	wg.key = key
	return nil
}

// ListenPort returns the current listen port of the wireguard interface.
func (wg *WireGuardInterface) ListenPort() (int, error) {
	return wg.opts.ListenPort, nil
}

// PutPeer updates a peer in the wireguard configuration.
func (wg *WireGuardInterface) PutPeer(ctx context.Context, peer *wireguard.Peer) error {
	wg.mu.Lock()
	defer wg.mu.Unlock()
	wg.peers[peer.ID] = *peer
	return nil
}

// DeletePeer removes a peer from the wireguard configuration.
func (wg *WireGuardInterface) DeletePeer(ctx context.Context, id string) error {
	wg.mu.Lock()
	defer wg.mu.Unlock()
	delete(wg.peers, id)
	return nil
}

// Peers returns the list of peers in the wireguard configuration.
func (wg *WireGuardInterface) Peers() map[string]wireguard.Peer {
	wg.mu.Lock()
	defer wg.mu.Unlock()
	out := make(map[string]wireguard.Peer, len(wg.peers))
	for k, v := range wg.peers {
		out[k] = v
	}
	return out
}

// Metrics returns the metrics for the wireguard interface and the host.
func (wg *WireGuardInterface) Metrics() (*v1.InterfaceMetrics, error) {
	wg.mu.Lock()
	defer wg.mu.Unlock()
	if wg.key == nil {
		return &v1.InterfaceMetrics{}, nil
	}
	encoded, err := wg.key.PublicKey().Encode()
	if err != nil {
		return nil, err
	}
	return &v1.InterfaceMetrics{
		DeviceName: wg.opts.Name,
		PublicKey:  encoded,
		AddressV4:  wg.Interface.AddressV4().String(),
		AddressV6:  wg.Interface.AddressV6().String(),
		Type:       "test-wireguard",
		ListenPort: int32(wg.opts.ListenPort),
		NumPeers:   int32(len(wg.peers)),
	}, nil
}

// Close closes the wireguard interface and all client connections.
func (wg *WireGuardInterface) Close(ctx context.Context) error {
	return nil
}
