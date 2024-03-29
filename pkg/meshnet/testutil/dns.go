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
)

// DNSManager is a mock dns manager.
type DNSManager struct {
	servers       []netip.AddrPort
	searchDomains []string
}

// Resolver returns a net.Resolver that can be used to resolve DNS names.
func (d *DNSManager) Resolver() *net.Resolver {
	return net.DefaultResolver
}

// AddServers adds the given dns servers to the system configuration.
func (d *DNSManager) AddServers(ctx context.Context, servers []netip.AddrPort) error {
	d.servers = append(d.servers, servers...)
	return nil
}

// AddServers adds the given dns servers to the system configuration.
func (d *DNSManager) AddSearchDomains(ctx context.Context, domains []string) error {
	d.searchDomains = append(d.searchDomains, domains...)
	return nil
}

// RefreshServers checks which peers in the database are offering DNS
// and updates the system configuration accordingly.
func (d *DNSManager) RefreshServers(ctx context.Context) error {
	return nil
}
