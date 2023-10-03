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
	"net"
	"net/netip"
	"sync"

	"github.com/webmeshproj/webmesh/pkg/meshnet"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system/firewall"
	"github.com/webmeshproj/webmesh/pkg/meshnet/wireguard"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// Manager is a test meshnet manager that mocks out all underlying
// network interfaces and system calls.
type Manager struct {
	nodeID types.NodeID
	db     storage.MeshDB
	opts   meshnet.Options
	wg     wireguard.Interface
	fw     firewall.Firewall
	peers  meshnet.PeerManager
	dns    meshnet.DNSManager
	netv4  netip.Prefix
	netv6  netip.Prefix
	masq   bool
	mu     sync.Mutex
}

// NewManager creates a new test network manager with a new in-memory database.
func NewManager(opts meshnet.Options, nodeID types.NodeID) meshnet.Manager {
	return NewManagerWithDB(meshdb.NewTestDB(), opts, nodeID)
}

// NewManagerWithDB creates a new test network manager using the given storage.
func NewManagerWithDB(db storage.MeshDB, opts meshnet.Options, nodeID types.NodeID) meshnet.Manager {
	return &Manager{
		nodeID: nodeID,
		db:     db,
		opts:   opts,
	}
}

// Start starts the network manager.
func (c *Manager) Start(ctx context.Context, opts meshnet.StartOptions) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var err error
	c.netv4 = opts.NetworkV4
	c.netv6 = opts.NetworkV6
	c.wg, err = NewWireGuardInterface(ctx, &wireguard.Options{
		NodeID:              c.nodeID,
		ListenPort:          c.opts.ListenPort,
		Name:                c.opts.InterfaceName,
		ForceName:           c.opts.ForceReplace,
		ForceTUN:            c.opts.ForceTUN,
		PersistentKeepAlive: c.opts.PersistentKeepAlive,
		MTU:                 c.opts.MTU,
		AddressV4:           opts.AddressV4,
		AddressV6:           opts.AddressV6,
		NetworkV4:           opts.NetworkV4,
		NetworkV6:           opts.NetworkV6,
		DisableIPv4:         c.opts.DisableIPv4,
		DisableIPv6:         c.opts.DisableIPv6,
	})
	if err != nil {
		return err
	}
	return nil
}

// NetworkV4 returns the current IPv4 network. The returned value may be invalid.
func (c *Manager) NetworkV4() netip.Prefix {
	return c.netv4
}

// NetworkV6 returns the current IPv6 network, even if it is disabled.
func (c *Manager) NetworkV6() netip.Prefix {
	return c.netv6
}

// StartMasquerade ensures that masquerading is enabled.
func (c *Manager) StartMasquerade(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.masq = true
	return nil
}

// DNS returns the DNS server manager. The DNS server manager is only
// available after Start has been called.
func (c *Manager) DNS() meshnet.DNSManager {
	return c.dns
}

// Peers return the peer manager.
func (c *Manager) Peers() meshnet.PeerManager {
	return c.peers
}

// Firewall returns the firewall.
// The firewall is only available after Start has been called.
func (c *Manager) Firewall() firewall.Firewall {
	return c.fw
}

// WireGuard returns the wireguard interface.
// The wireguard interface is only available after Start has been called.
func (c *Manager) WireGuard() wireguard.Interface {
	return c.wg
}

func (c *Manager) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

// Close closes the network manager and cleans up any resources.
func (c *Manager) Close(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return nil
}
