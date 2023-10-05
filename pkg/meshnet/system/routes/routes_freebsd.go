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
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/webmeshproj/webmesh/pkg/common"
)

// GetDefaultGateway returns the default gateway of the current system.
func GetDefaultGateway(ctx context.Context) (Gateway, error) {
	var gateway Gateway
	out, err := common.ExecOutput(ctx, "route", "-n", "get", "default")
	if err != nil {
		return gateway, fmt.Errorf("failed to get default gateway: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			var err error
			gateway.Addr, err = netip.ParseAddr(strings.TrimSpace(line[8:]))
			if err != nil {
				return gateway, fmt.Errorf("failed to parse gateway address: %w", err)
			}
			gateway.Name = "default"
			return gateway, nil
		}
	}
	return gateway, errors.New("no default gateway found")
}

// SetDefaultIPv4Gateway sets the default IPv4 gateway for the current system.
func SetDefaultIPv4Gateway(ctx context.Context, gateway Gateway) error {
	return errors.New("not implemented")
}

// SetDefaultIPv6Gateway sets the default IPv6 gateway for the current system.
func SetDefaultIPv6Gateway(ctx context.Context, gateway Gateway) error {
	return errors.New("not implemented")
}

// Add adds a route to the interface with the given name.
func Add(ctx context.Context, ifaceName string, addr netip.Prefix) error {
	out, err := common.ExecOutput(ctx, "route", "-n", "add", "-"+getFamily(addr.Addr()), addr.String(), "-interface", ifaceName)
	if err != nil {
		if strings.Contains(string(out), "already in table") || strings.Contains(string(out), "exists") {
			return ErrRouteExists
		}
		return err
	}
	return nil
}

// Remove removes a route from the interface with the given name.
func Remove(ctx context.Context, ifaceName string, addr netip.Prefix) error {
	return common.Exec(ctx, "route", "-n", "delete", "-"+getFamily(addr.Addr()), addr.String(), "-interface", ifaceName)
}

func getFamily(addr netip.Addr) string {
	if addr.Is4() {
		return "inet"
	}
	return "inet6"
}
