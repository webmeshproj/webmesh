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

package util

import (
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"
)

func ifaceNetwork(ifaceName string, forAddr netip.Addr, ipv6 bool) (netip.Prefix, error) {
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
	// Find which address is the closest to the desired address.
	for _, a := range addrs {
		if a.Contains(forAddr.AsSlice()) {
			ip, _ := netip.ParseAddr(a.IP.String())
			ones, _ := a.Mask.Size()
			return netip.PrefixFrom(ip, ones), nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("no matching address found for interface %s", ifaceName)
}
