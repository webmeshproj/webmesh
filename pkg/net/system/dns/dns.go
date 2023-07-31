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

// Package dns contains utility functions for DNS.
package dns

import (
	"net/netip"
	"time"
)

var defaultNS = []string{"127.0.0.1:53", "[::1]:53"}

var defaultConfig = DNSConfig{
	Servers:  defaultNS,
	Search:   []string{},
	Ndots:    1,
	Timeout:  5 * time.Second,
	Attempts: 2,
	UseTCP:   false,
}

func init() {
	syscfg, err := loadSystemConfig()
	if err != nil {
		return
	}
	defaultConfig = *syscfg
}

// DNSConfig is a configuration for performing DNS lookups.
type DNSConfig struct {
	// Servers is the list of DNS servers to use.
	Servers []string
	// Search is the list of search domains to use.
	Search []string
	// Ndots is the number of dots required for absolute name.
	Ndots int
	// Timeout is the DNS timeout.
	Timeout time.Duration
	// Attempts is the number of DNS attempts.
	Attempts int
	// UseTCP indicates whether to use TCP for DNS.
	UseTCP bool
}

// GetSystemConfig returns the system DNS configuration.
func GetSystemConfig() DNSConfig {
	return defaultConfig
}

// AddServers adds DNS servers to the system configuration. On Windows
// the interface name is required.
func AddServers(iface string, servers []netip.AddrPort) error {
	return addServers(iface, servers)
}

// RemoveServers removes DNS servers from the system configuration. On Windows
// the interface name is required.
func RemoveServers(iface string, servers []netip.AddrPort) error {
	return removeServers(iface, servers)
}
