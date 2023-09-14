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
	"context"
	"net/netip"
	"strings"

	"github.com/webmeshproj/webmesh/pkg/util"
)

// ActivateInterface activates the interface with the given name.
func ActivateInterface(ctx context.Context, name string) error {
	out, err := util.ExecOutput(ctx, "ifconfig", name, "up")
	if err != nil {
		if strings.Contains(string(out), "not exist") {
			return ErrLinkNotExists
		}
		return err
	}
	return nil
}

// DeactivateInterface deactivates the interface with the given name.
func DeactivateInterface(ctx context.Context, name string) error {
	out, err := util.ExecOutput(ctx, "ifconfig", name, "down")
	if err != nil {
		if strings.Contains(string(out), "not exist") {
			return ErrLinkNotExists
		}
		return err
	}
	return nil
}

// RemoveInterface removes the given interface.
func RemoveInterface(ctx context.Context, ifaceName string) error {
	out, err := util.ExecOutput(ctx, "ifconfig", ifaceName, "destroy")
	if err != nil {
		if strings.Contains(string(out), "not exist") {
			return ErrLinkNotExists
		}
		return err
	}
	return nil
}

// InterfaceNetwork returns the network for the given interface and address.
func InterfaceNetwork(ifaceName string, forAddr netip.Addr, ipv6 bool) (netip.Prefix, error) {
	// We just return back the final address in the zone with a /32 or /128 mask.
	// This is because we don't know the subnet mask of the interface.
	// We could try to parse the output of ifconfig, but that's not portable.
	if ipv6 {
		return netip.PrefixFrom(forAddr, 128), nil
	}
	return netip.PrefixFrom(forAddr, 32), nil
}
s