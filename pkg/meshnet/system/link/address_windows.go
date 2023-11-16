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
	"fmt"
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// SetInterfaceAddress sets the address of the interface with the given name.
func SetInterfaceAddress(ctx context.Context, name string, addr netip.Prefix) error {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("net link by name: %w", err)
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(link.Index))
	if err != nil {
		return fmt.Errorf("winipcfg luid from index: %w", err)
	}
	err = luid.AddIPAddress(addr)
	if err != nil {
		return fmt.Errorf("winipcfg add ip address: %w", err)
	}
	return nil
}

// RemoveInterfaceAddress removes the address of the interface with the given name.
func RemoveInterfaceAddress(_ context.Context, name string, addr netip.Prefix) error {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("net link by name: %w", err)
	}
	luid, err := winipcfg.LUIDFromIndex(uint32(link.Index))
	if err != nil {
		return fmt.Errorf("winipcfg luid from index: %w", err)
	}
	err = luid.DeleteIPAddress(addr)
	if err != nil {
		return fmt.Errorf("winipcfg delete ip address: %w", err)
	}
	return nil
}
