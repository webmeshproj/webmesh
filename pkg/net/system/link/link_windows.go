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

package link

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/webmeshproj/webmesh/pkg/util"
)

// Below functions are no-ops on Windows except for InterfaceNetwork.

// ActivateInterface activates the interface with the given name.
func ActivateInterface(ctx context.Context, name string) error {
	return nil
}

// DeactivateInterface deactivates the interface with the given name.
func DeactivateInterface(ctx context.Context, name string) error {
	return nil
}

// RemoveInterface removes the given interface.
func RemoveInterface(ctx context.Context, ifaceName string) error {
	return nil
}

// InterfaceNetwork returns the network for the given interface and address.
func InterfaceNetwork(ifaceName string, forAddr netip.Addr, ipv6 bool) (netip.Prefix, error) {
	out, err := util.ExecOutput(context.Background(),
		"wmic", "nic", "where", "ipenabled=true", "get", "ipaddress,ipsubnet", "/format:csv")
	if err != nil {
		return netip.Prefix{}, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 2 {
			continue
		}
		ips := wmicStrToSlice(fields[len(fields)-2])
		subnetMasks := wmicStrToSlice(fields[len(fields)-1])
		for i, ip := range ips {
			subnetMask := subnetMasks[i]
			if ip == forAddr.String() {
				if forAddr.Is4() {
					// Convert the mask to the prefix length
					stringMask := net.IPMask(net.ParseIP(subnetMask).To4())
					length, _ := stringMask.Size()
					subnetMask = strconv.Itoa(length)
				}
				prefix, err := netip.ParsePrefix(ip + "/" + subnetMask)
				if err != nil {
					return netip.Prefix{}, err
				}
				return prefix, nil
			}
		}
	}
	return netip.Prefix{}, nil
}

func wmicStrToSlice(s string) []string {
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	return strings.Split(s, ",")
}
