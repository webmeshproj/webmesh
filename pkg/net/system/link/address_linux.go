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
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"github.com/jsimonetti/rtnetlink"
	"golang.org/x/exp/slog"
	"golang.org/x/sys/unix"
)

// SetInterfaceAddress sets the address of the interface with the given name.
func SetInterfaceAddress(ctx context.Context, name string, addr netip.Prefix) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("get interface by name: %w", err)
	}

	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Detect network family
	family := unix.AF_INET6
	if addr.Addr().Is4() {
		family = unix.AF_INET
	}

	// Calculate the prefix length
	ones := addr.Bits()

	// Calculate the broadcast IP - only used when family is AF_INET
	var brd net.IP
	if addr.Addr().Is4() {
		to4 := addr.Addr().AsSlice()
		mask := net.CIDRMask(ones, 32)
		brd = make(net.IP, len(to4))
		binary.BigEndian.PutUint32(brd, binary.BigEndian.Uint32(to4)|^binary.BigEndian.Uint32(net.IP(mask).To4()))
	}

	req := &rtnetlink.AddressMessage{
		Family:       uint8(family),
		PrefixLength: uint8(ones),
		Scope:        unix.RT_SCOPE_UNIVERSE,
		Index:        uint32(iface.Index),
		Attributes: &rtnetlink.AddressAttributes{
			Address:   addr.Addr().AsSlice(),
			Local:     addr.Addr().AsSlice(),
			Broadcast: brd,
		},
	}
	slog.Default().With("addr", "add").
		Debug("adding address", slog.Any("request", req))
	// Add the address to the interface
	err = conn.Address.New(req)
	if err != nil {
		return fmt.Errorf("add address to interface: %w", err)
	}
	return nil
}
