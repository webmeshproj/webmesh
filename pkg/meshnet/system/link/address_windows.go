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
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/webmeshproj/webmesh/pkg/common"
)

// SetInterfaceAddress sets the address of the interface with the given name.
func SetInterfaceAddress(ctx context.Context, name string, addr netip.Prefix) error {
	_, ipnet, err := net.ParseCIDR(addr.String())
	if err != nil {
		return err
	}
	family := "ipv4"
	mask := net.IP(ipnet.Mask).String()
	if addr.Addr().Is6() {
		family = "ipv6"
		mask = fmt.Sprintf("%d", addr.Bits())
	}
	err = common.Exec(ctx, "netsh", "interface", family, "set", "address",
		fmt.Sprintf("%q", name),
		addr.Addr().String(),
		"store=active",
	)
	if err != nil {
		return err
	}
	return nil
}

// RemoveInterfaceAddress removes the address of the interface with the given name.
func RemoveInterfaceAddress(_ context.Context, name string, addr netip.Prefix) error {
	return errors.New("not implemented")
}
