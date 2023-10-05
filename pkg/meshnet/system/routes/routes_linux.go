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

package routes

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// GetDefaultGateway returns the default gateway of the current system.
func GetDefaultGateway(_ context.Context) (Gateway, error) {
	var gateway Gateway
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return gateway, fmt.Errorf("could not open /proc/net/route: %w", err)
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
		gateway.Addr, err = decodeKernelHexIP(fields[2])
		if err != nil {
			return gateway, fmt.Errorf("could not decode gateway IP: %w", err)
		}
		gateway.Name = fields[0]
		return gateway, nil
	}
	if err := scanner.Err(); err != nil {
		return gateway, fmt.Errorf("could not read /proc/net/route: %w", err)
	}
	return gateway, errors.New("could not determine current default gateway")
}

// SetDefaultIPv4Gateway sets the default IPv4 gateway for the current system.
func SetDefaultIPv4Gateway(ctx context.Context, gateway Gateway) error {
	link, err := netlink.LinkByName(gateway.Name)
	if err != nil {
		return fmt.Errorf("get link by name: %w", err)
	}
	err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Gw:        gateway.Addr.AsSlice(),
		Dst: &net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.IPv4Mask(0, 0, 0, 0),
		},
	})
	if err != nil {
		return fmt.Errorf("set default IPv4 gateway: %w", err)
	}
	return nil
}

// SetDefaultIPv6Gateway sets the default IPv6 gateway for the current system.
func SetDefaultIPv6Gateway(ctx context.Context, gateway Gateway) error {
	return errors.New("not implemented")
}

// Add adds a route to the interface with the given name.
func Add(ctx context.Context, ifaceName string, addr netip.Prefix) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("get link by name: %w", err)
	}
	ones := addr.Bits()
	rt := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   addr.Masked().Addr().AsSlice(),
			Mask: net.CIDRMask(ones, 8*len(addr.Addr().AsSlice())),
		},
	}
	context.LoggerFrom(ctx).Debug("Adding route to interface", slog.Any("route", rt.Dst))
	err = netlink.RouteAdd(rt)
	if err != nil {
		if strings.Contains(err.Error(), "file exists") || errors.Is(err, os.ErrExist) {
			return ErrRouteExists
		}
		return fmt.Errorf("add route to interface: %w", err)
	}
	return nil
}

// Remove removes a route from the interface with the given name.
func Remove(ctx context.Context, ifaceName string, addr netip.Prefix) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("get link by name: %w", err)
	}
	ones := addr.Bits()
	rt := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   addr.Masked().Addr().AsSlice(),
			Mask: net.CIDRMask(ones, 8*len(addr.Addr().AsSlice())),
		},
	}
	context.LoggerFrom(ctx).Debug("Removing route from interface", slog.Any("route", rt.Dst))
	err = netlink.RouteDel(rt)
	if err != nil {
		if strings.Contains(err.Error(), "no such process") || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("remove route from interface: %w", err)
	}
	return nil
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
