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
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/jsimonetti/rtnetlink"
	"github.com/vishvananda/netlink"
)

// EnableIPForwarding enables IP forwarding.
func EnableIPForwarding() error {
	on := []byte("1")
	mode := fs.FileMode(0644)
	err := os.WriteFile("/proc/sys/net/ipv4/conf/all/forwarding", on, mode)
	if err != nil {
		return fmt.Errorf("failed to enable IPv4 forwarding: %w", err)
	}
	// Write to the legacy configuration file
	err = os.WriteFile("/proc/sys/net/ipv4/ip_forward", on, mode)
	if err != nil {
		return fmt.Errorf("failed to enable IPv4 forwarding: %w", err)
	}
	err = os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", on, mode)
	if err != nil {
		return fmt.Errorf("failed to enable IPv6 forwarding: %w", err)
	}
	return nil
}

// RemoveInterface removes the given interface.
func RemoveInterface(ifaceName string) error {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface: %w", err)
	}
	return conn.Link.Delete(uint32(iface.Index))
}

// GetDefaultGateway returns the default gateway of the current system.
func GetDefaultGateway(ctx context.Context) (netip.Addr, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}, fmt.Errorf("could not open /proc/net/route: %w", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		// Skip non-default routes.
		// Second field is the destination and should be 00000000.
		// Eighth field is the mask and should be 00000000.
		if fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		// The gateway IP is in the 3rd field of the route encoded as a hex string.
		return decodeKernelHexIP(fields[2])
	}
	if err := scanner.Err(); err != nil {
		return netip.Addr{}, fmt.Errorf("could not read /proc/net/route: %w", err)
	}
	return netip.Addr{}, errors.New("could not determine current default gateway")
}

func decodeKernelHexIP(hexIP string) (netip.Addr, error) {
	ip, err := hex.DecodeString(hexIP)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("could not decode IP: %w", err)
	}
	// IPs in kernel files are returned in network byte order
	// so we need to reverse it.
	for i, j := 0, len(ip)-1; i < j; i, j = i+1, j-1 {
		ip[i], ip[j] = ip[j], ip[i]
	}
	out, _ := netip.AddrFromSlice(ip)
	return out, nil
}

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
