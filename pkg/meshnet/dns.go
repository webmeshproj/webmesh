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
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system/dns"
	"github.com/webmeshproj/webmesh/pkg/meshnet/wireguard"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// DNSManager is an interface for managing DNS nameservers on the local system.
type DNSManager interface {
	// Resolver returns a net.Resolver that can be used to resolve DNS names.
	Resolver() *net.Resolver
	// AddServers adds the given dns servers to the system configuration.
	AddServers(ctx context.Context, servers []netip.AddrPort) error
	// RefreshServers checks which peers in the database are offering DNS
	// and updates the system configuration accordingly.
	RefreshServers(ctx context.Context) error
}

type dnsManager struct {
	wg             wireguard.Interface
	storage        storage.MeshDB
	localdnsaddr   netip.AddrPort
	dnsservers     []netip.AddrPort
	noIPv4, noIPv6 bool
	mu             sync.RWMutex
}

// Resolver returns a net.Resolver that can be used to resolve DNS names.
func (d *dnsManager) Resolver() *net.Resolver {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.localdnsaddr.IsValid() {
		return &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, d.localdnsaddr.String())
			},
		}
	}
	if len(d.dnsservers) == 0 {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, d.dnsservers[0].String())
		},
	}
}

// AddServers adds the given dns servers to the system configuration.
func (m *dnsManager) AddServers(ctx context.Context, servers []netip.AddrPort) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	context.LoggerFrom(ctx).Debug("Configuring DNS servers", slog.Any("servers", servers))
	err := dns.AddServers(m.wg.Name(), servers)
	if err != nil {
		return fmt.Errorf("add dns servers: %w", err)
	}
	m.dnsservers = append(m.dnsservers, servers...)
	return nil
}

// RefreshServers checks which peers in the database are offering DNS
// and updates the system configuration accordingly.
func (m *dnsManager) RefreshServers(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	context.LoggerFrom(ctx).Debug("Refreshing MeshDNS servers")
	servers, err := m.storage.Peers().ListByFeature(ctx, v1.Feature_MESH_DNS)
	if err != nil {
		return fmt.Errorf("list peers with feature: %w", err)
	}
	seen := make(map[netip.AddrPort]bool)
	for _, server := range servers {
		if server.PrivateDNSAddrV4().IsValid() && !m.noIPv4 {
			seen[server.PrivateDNSAddrV4()] = true
		}
	}
	// Find out which (if any) DNS servers we are removing
	toRemove := make([]netip.AddrPort, 0)
	for _, server := range m.dnsservers {
		if _, ok := seen[server]; !ok {
			toRemove = append(toRemove, server)
		} else if ok {
			// We don't need to readd them
			seen[server] = false
		}
	}
	// Reset our dnsservers and determine which servers to add
	// to the system
	m.dnsservers = make([]netip.AddrPort, 0)
	toAdd := make([]netip.AddrPort, 0)
	if m.localdnsaddr.IsValid() {
		toAdd = append(toAdd, m.localdnsaddr)
	}
	for server, needsAdd := range seen {
		m.dnsservers = append(m.dnsservers, server)
		if needsAdd {
			toAdd = append(toAdd, server)
		}
	}
	// Add the new servers first
	if len(toAdd) > 0 {
		err := dns.AddServers(m.wg.Name(), toAdd)
		if err != nil {
			return fmt.Errorf("add dns servers: %w", err)
		}
	}
	// Remove the old servers
	if len(toRemove) > 0 {
		err := dns.RemoveServers(m.wg.Name(), toRemove)
		if err != nil {
			return fmt.Errorf("remove dns servers: %w", err)
		}
	}
	return nil
}
