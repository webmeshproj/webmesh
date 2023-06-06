/*
Copyright 2023.

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

package util

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
)

// EndpointDetectOpts contains options for endpoint detection.
type EndpointDetectOpts struct {
	// DetectIPv6 enables IPv6 detection.
	DetectIPv6 bool
	// DetectPrivate enables private address detection.
	DetectPrivate bool
	// AllowRemoteDetection enables remote address detection.
	AllowRemoteDetection bool
	// SkipInterfaces contains a list of interfaces to skip.
	SkipInterfaces []string
}

type PrefixList []netip.Prefix

func (a PrefixList) Contains(addr netip.Addr) bool {
	for _, prefix := range a {
		if prefix.Addr().Compare(addr) == 0 || prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (a PrefixList) Strings() []string {
	var out []string
	for _, addr := range a {
		out = append(out, addr.String())
	}
	return out
}

func (a PrefixList) AddrStrings() []string {
	var out []string
	for _, addr := range a {
		out = append(out, addr.Addr().String())
	}
	return out
}

func (a PrefixList) Len() int      { return len(a) }
func (a PrefixList) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

// Sort by IPv4 addresses first, then IPv6 addresses.
func (a PrefixList) Less(i, j int) bool {
	iis4 := a[i].Addr().Is4()
	jis4 := a[j].Addr().Is4()
	if iis4 && !jis4 {
		return true
	}
	if !iis4 && jis4 {
		return false
	}
	return a[i].Addr().Less(a[j].Addr())
}

// DetectEndpoints detects endpoints for this machine.
func DetectEndpoints(ctx context.Context, opts EndpointDetectOpts) (PrefixList, error) {
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
				addrs = append(addrs, netip.PrefixFrom(addr, 32))
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

func detectFromInterfaces(opts *EndpointDetectOpts) (PrefixList, error) {
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
		if Contains(opts.SkipInterfaces, iface.Name) {
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
				prefix, err := ifaceNetwork(iface.Name, true)
				if err != nil {
					return nil, fmt.Errorf("failed to get network for interface %s: %w", iface.Name, err)
				}
				ips = append(ips, prefix)
			}
			if addr.Is4() {
				prefix, err := ifaceNetwork(iface.Name, false)
				if err != nil {
					return nil, fmt.Errorf("failed to get network for interface %s: %w", iface.Name, err)
				}
				ips = append(ips, prefix)
			}
		}
	}
	return ips, nil
}

// TODO: This is a linux-only implementation.
func ifaceNetwork(ifaceName string, ipv6 bool) (netip.Prefix, error) {
	family := netlink.FAMILY_V4
	if ipv6 {
		family = netlink.FAMILY_V6
	}
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return netip.Prefix{}, err
	}
	addrs, err := netlink.AddrList(link, family)
	if err != nil {
		return netip.Prefix{}, err
	}
	if len(addrs) == 0 {
		return netip.Prefix{}, fmt.Errorf("no addresses found for interface %s", ifaceName)
	}
	// Return the first address on the interface.
	addr := addrs[0]
	ip, _ := netip.ParseAddr(addr.IP.String())
	ones, _ := addr.Mask.Size()
	return netip.PrefixFrom(ip, ones), nil
}
