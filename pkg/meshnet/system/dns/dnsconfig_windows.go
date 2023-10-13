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

package dns

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func addServers(iface string, servers []netip.AddrPort) error {
	// Just use netsh
	for i, server := range servers {
		family := "ipv4"
		if server.Addr().Is6() {
			family = "ipv6"
		}
		args := []string{
			"interface", family, "add", "dnsserver", iface,
			fmt.Sprintf("address=%s", server.Addr().String()),
			fmt.Sprintf("index=%d", i),
		}
		if server.Port() != 53 {
			args = append(args, fmt.Sprintf("validate=no"))
		}
		cmd := exec.Command("netsh", args...)
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}

func addSearchDomains(iface string, domains []string) error {
	// Just use netsh
	for i, domain := range domains {
		args := []string{
			"interface", "ip", "add", "dnsserver", iface,
			fmt.Sprintf("search=%s", domain),
			fmt.Sprintf("index=%d", i),
		}
		cmd := exec.Command("netsh", args...)
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}

func removeServers(iface string, servers []netip.AddrPort) error {
	// Just use netsh
	for _, server := range servers {
		family := "ipv4"
		if server.Addr().Is6() {
			family = "ipv6"
		}
		args := []string{
			"interface", family, "delete", "dnsserver", iface,
			fmt.Sprintf("address=%s", server.Addr().String()),
		}
		cmd := exec.Command("netsh", args...)
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}

func removeSearchDomains(iface string, domains []string) error {
	// Just use netsh
	for _, domain := range domains {
		args := []string{
			"interface", "ip", "delete", "dnsserver", iface,
			fmt.Sprintf("search=%s", domain),
		}
		cmd := exec.Command("netsh", args...)
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}

func loadSystemConfig() (*DNSConfig, error) {
	l := uint32(20000)
	b := make([]byte, l)

	if err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_PREFIX, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &l); err != nil {
		return nil, err
	}
	var addresses []*windows.IpAdapterAddresses
	for addr := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])); addr != nil; addr = addr.Next {
		addresses = append(addresses, addr)
	}

	resolvers := map[string]bool{}
	for _, addr := range addresses {
		for next := addr.FirstUnicastAddress; next != nil; next = next.Next {
			if addr.OperStatus != windows.IfOperStatusUp {
				continue
			}
			if next.Address.IP() != nil {
				for dnsServer := addr.FirstDnsServerAddress; dnsServer != nil; dnsServer = dnsServer.Next {
					ip := dnsServer.Address.IP()
					if ip.IsMulticast() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
						continue
					}
					if ip.To16() != nil && strings.HasPrefix(ip.To16().String(), "fec0:") {
						continue
					}
					resolvers[ip.String()] = true
				}
				break
			}
		}
	}

	// Take unique values only
	servers := []string{}
	for server := range resolvers {
		servers = append(servers, server)
	}
	if len(servers) == 0 {
		servers = defaultNS
	}

	// TODO: Make configurable, based on defaults in https://github.com/miekg/dns/blob/master/clientconfig.go
	return &DNSConfig{
		Servers:  servers,
		Search:   []string{},
		Ndots:    1,
		Timeout:  5 * time.Second,
		Attempts: 1,
	}, nil
}
