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
	"errors"
	"fmt"
	"net/netip"

	"github.com/vishvananda/netlink"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// SetInterfaceAddress sets the address of the interface with the given name.
func SetInterfaceAddress(_ context.Context, name string, addr netip.Prefix) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		var notExistsErr *netlink.LinkNotFoundError
		if errors.As(err, &notExistsErr) {
			return ErrLinkNotExists
		}
		return err
	}
	nladdr, err := netlink.ParseAddr(addr.String())
	if err != nil {
		return fmt.Errorf("netlink parse addr: %w", err)
	}
	return netlink.AddrAdd(link, nladdr)
}

// RemoveInterfaceAddress removes the address of the interface with the given name.
func RemoveInterfaceAddress(_ context.Context, name string, addr netip.Prefix) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		var notExistsErr *netlink.LinkNotFoundError
		if errors.As(err, &notExistsErr) {
			return ErrLinkNotExists
		}
		return err
	}
	nladdr, err := netlink.ParseAddr(addr.String())
	if err != nil {
		return fmt.Errorf("netlink parse addr: %w", err)
	}
	return netlink.AddrDel(link, nladdr)
}
