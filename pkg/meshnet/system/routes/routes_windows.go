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
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/webmeshproj/webmesh/pkg/common"
)

// GetDefaultGateway returns the default gateway of the current system.
func GetDefaultGateway(ctx context.Context) (Gateway, error) {
	return defaultGatewayIPConfig(ctx)
}

// SetDefaultIPv4Gateway sets the default IPv4 gateway for the current system.
func SetDefaultIPv4Gateway(ctx context.Context, gateway Gateway) error {
	return errors.New("not implemented")
}

// Add adds a route to the interface with the given name.
func Add(ctx context.Context, name string, addr netip.Prefix) error {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("net link by name: %w", err)
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(link.Index))
	if err != nil {
		return fmt.Errorf("winipcfg luid from index: %w", err)
	}
	nextHop, err := getNextHopForLink(luid, addr)
	if err != nil {
		return fmt.Errorf("get next hop for link: %w", err)
	}
	err = luid.AddRoute(addr, nextHop, 0)
	if err != nil {
		return fmt.Errorf("winipcfg add route: %w", err)
	}
	return nil
}

// Remove removes a route from the interface with the given name.
func Remove(ctx context.Context, name string, addr netip.Prefix) error {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("net link by name: %w", err)
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(link.Index))
	if err != nil {
		return fmt.Errorf("winipcfg luid from index: %w", err)
	}
	nextHop, err := getNextHopForLink(luid, addr)
	if err != nil {
		return fmt.Errorf("get next hop for link: %w", err)
	}
	err = luid.DeleteRoute(addr, nextHop)
	if err != nil {
		return fmt.Errorf("winipcfg delete route: %w", err)
	}
	return nil
}

func getNextHopForLink(luid winipcfg.LUID, route netip.Prefix) (netip.Addr, error) {
	var family winipcfg.AddressFamily
	if route.Addr().Is4() {
		family = windows.AF_INET
	} else {
		family = windows.AF_INET6
	}
	addrs, err := winipcfg.GetUnicastIPAddressTable(family)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, addr := range addrs {
		if addr.InterfaceLUID == luid {
			return addr.Address.Addr(), nil
		}
	}
	return netip.Addr{}, errors.New("no address found for interface")
}

func defaultGatewayIPConfig(ctx context.Context) (Gateway, error) {
	var gateway Gateway
	out, err := common.ExecOutput(ctx, "ipconfig")
	if err != nil {
		return gateway, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Default Gateway") {
			fields := strings.Fields(line)
			var err error
			gateway.Addr, err = netip.ParseAddr(fields[len(fields)-1])
			if err != nil {
				return gateway, err
			}
			gateway.Name = fields[2]
			return gateway, nil
		}
	}
	return gateway, nil
}
