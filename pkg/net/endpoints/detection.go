//go:build !wasm

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

package endpoints

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/webmeshproj/webmesh/pkg/net/system/link"
)

// Detect detects endpoints for this machine.
func Detect(ctx context.Context, opts DetectOpts) (PrefixList, error) {
	addrs, err := detectFromInterfaces(&opts)
	if err != nil {
		return nil, err
	}
	if opts.AllowRemoteDetection {
		detected, err := DetectPublicAddresses(ctx)
		if err != nil {
			return nil, fmt.Errorf("detect public address: %w", err)
		}
		for _, addr := range detected {
			if !addrs.Contains(addr) {
				if addr.Is6() && !opts.DetectIPv6 {
					continue
				}
				addrs = append(addrs, netip.PrefixFrom(addr, func() int {
					if addr.Is4() {
						return 32
					}
					return 128
				}()))
			}
		}
	}
	return addrs, nil
}

// DetectPublicAddresses detects the public addresses of the machine
// using the opendns resolver service.
func DetectPublicAddresses(ctx context.Context) ([]netip.Addr, error) {
	const myip = "myip.opendns.com"
	const dnsaddr = "resolver1.opendns.com"
	const timeout = 5 * time.Second
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", dnsaddr)
	if err != nil {
		return nil, fmt.Errorf("lookup %s: %w", dnsaddr, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no resolvers found for detection")
	}
	var ipv4, ipv6 netip.Addr
	for _, addr := range addrs {
		if addr.Is4() {
			ipv4 = addr
		} else if addr.Is6() {
			ipv6 = addr
		}
	}
	ip4Resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return net.DialTimeout(network, net.JoinHostPort(ipv4.String(), "53"), timeout)
		},
	}
	ip6Resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return net.DialTimeout(network, net.JoinHostPort(ipv6.String(), "53"), timeout)
		},
	}
	var out []netip.Addr
	if ipv4.IsValid() {
		ips, err := ip4Resolver.LookupNetIP(ctx, "ip4", myip)
		if err == nil {
			out = append(out, ips...)
		}
	}
	if ipv6.IsValid() {
		ips, err := ip6Resolver.LookupNetIP(ctx, "ip6", myip)
		if err == nil {
			out = append(out, ips...)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no addresses found")
	}
	return out, nil
}

func detectFromInterfaces(opts *DetectOpts) (PrefixList, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	var ips PrefixList
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		if slices.Contains(opts.SkipInterfaces, iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("failed to list addresses for interface %s: %w", iface.Name, err)
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				return nil, fmt.Errorf("failed to parse address %s: %w", addr.String(), err)
			}
			addr, err := netip.ParseAddr(ip.String())
			if err != nil {
				return nil, fmt.Errorf("failed to parse address %s: %w", ip.String(), err)
			}
			if addr.IsPrivate() && !opts.DetectPrivate {
				continue
			}
			if addr.Is6() && opts.DetectIPv6 {
				prefix, err := link.InterfaceNetwork(iface.Name, addr, true)
				if err != nil {
					return nil, fmt.Errorf("failed to get network for interface %s: %w", iface.Name, err)
				}
				ips = append(ips, prefix)
			}
			if addr.Is4() {
				prefix, err := link.InterfaceNetwork(iface.Name, addr, false)
				if err != nil {
					return nil, fmt.Errorf("failed to get network for interface %s: %w", iface.Name, err)
				}
				ips = append(ips, prefix)
			}
		}
	}
	return ips, nil
}
