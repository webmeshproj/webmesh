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

package system

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/jsimonetti/rtnetlink"
	"golang.org/x/exp/slog"
	"golang.org/x/sys/unix"
	"pault.ag/go/modprobe"
)

func newInterface(ctx context.Context, opts *Options) (Interface, error) {
	if opts.MTU == 0 {
		opts.MTU = DefaultMTU
	}
	if opts.ForceTUN {
		return NewTUN(ctx, opts)
	}
	logger := slog.Default().With(
		slog.String("component", "wireguard"),
		slog.String("type", "kernel"),
		slog.String("facility", "device"))
	if opts.Modprobe {
		err := modprobe.Load("wireguard", "")
		if err != nil {
			// Try to fallback to TUN
			logger.Error("load wireguard kernel module, falling back to TUN", slog.String("error", err.Error()))
			return NewTUN(ctx, opts)
		}
	}
	if !opts.DefaultGateway.IsValid() {
		defaultGateway, err := GetDefaultGateway(ctx)
		if err != nil {
			return nil, fmt.Errorf("detect current default gateway")
		}
		opts.DefaultGateway = defaultGateway
	}
	iface := &linuxKernelInterface{
		opts: opts,
		log:  logger,
	}
	return iface, iface.create(ctx)
}

// EnableIPForwarding enables IP forwarding.
func EnableIPForwarding() error {
	on := []byte("1")
	mode := fs.FileMode(0644)
	err := os.WriteFile("/proc/sys/net/ipv4/conf/all/forwarding", on, mode)
	if err != nil {
		return fmt.Errorf("failed to enable IPv4 forwarding: %w", err)
	}
	// Write to the legacy configuration file
	err = os.WriteFile("/proc/sys/net/ipv4/ip_forward", on, mode)
	if err != nil {
		return fmt.Errorf("failed to enable IPv4 forwarding: %w", err)
	}
	err = os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", on, mode)
	if err != nil {
		return fmt.Errorf("failed to enable IPv6 forwarding: %w", err)
	}
	return nil
}

// RemoveInterface removes the given interface.
func RemoveInterface(ifaceName string) error {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface: %w", err)
	}
	return conn.Link.Delete(uint32(iface.Index))
}

// GetDefaultGateway returns the default gateway of the current system.
func GetDefaultGateway(ctx context.Context) (netip.Addr, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}, fmt.Errorf("could not open /proc/net/route: %w", err)
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
		return decodeKernelHexIP(fields[2])
	}
	if err := scanner.Err(); err != nil {
		return netip.Addr{}, fmt.Errorf("could not read /proc/net/route: %w", err)
	}
	return netip.Addr{}, errors.New("could not determine current default gateway")
}

// ActivateInterface activates the interface with the given name.
func ActivateInterface(ctx context.Context, name string) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("get interface: %w", err)
	}
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	// Request the details of the interface
	msg, err := conn.Link.Get(uint32(iface.Index))
	if err != nil {
		return fmt.Errorf("get interface details: %w", err)
	}
	// Check if the interface is already up
	state := msg.Attributes.OperationalState
	if state == rtnetlink.OperStateUp || state == rtnetlink.OperStateUnknown {
		return nil
	}
	req := &rtnetlink.LinkMessage{
		Family: unix.AF_UNSPEC,
		Type:   msg.Type,
		Index:  uint32(iface.Index),
		Flags:  unix.IFF_UP,
		Change: unix.IFF_UP,
	}
	slog.Default().Debug("set interface up",
		slog.Any("request", req),
		slog.String("interface", iface.Name))
	err = conn.Link.Set(req)
	if err != nil {
		return fmt.Errorf("set interface up: %w", err)
	}
	return nil
}

// DeactivateInterface deactivates the interface with the given name.
func DeactivateInterface(ctx context.Context, name string) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("get interface: %w", err)
	}
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	// Request the details of the interface
	msg, err := conn.Link.Get(uint32(iface.Index))
	if err != nil {
		return fmt.Errorf("get interface details: %w", err)
	}
	// Check if the interface is already down
	state := msg.Attributes.OperationalState
	if state == rtnetlink.OperStateDown {
		return nil
	}
	req := &rtnetlink.LinkMessage{
		Family: 0x0,
		Type:   msg.Type,
		Index:  uint32(iface.Index),
		Flags:  0x0,
		Change: 0x1,
	}
	slog.Default().Debug("deactivate interface", slog.Any("request", req))
	err = conn.Link.Set(req)
	if err != nil {
		return fmt.Errorf("set interface down: %w", err)
	}
	return nil
}

// DestroyInterface destroys the interface with the given name.
func DestroyInterface(ctx context.Context, name string) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("get interface: %w", err)
	}
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	slog.Default().Debug("destroying network interface", slog.String("name", name))
	err = conn.Link.Delete(uint32(iface.Index))
	if err != nil {
		return fmt.Errorf("delete interface: %w", err)
	}
	return nil
}

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

// AddRoute adds a route to the interface with the given name.
func AddRoute(ctx context.Context, ifaceName string, addr netip.Prefix) error {
	iface, err := net.InterfaceByName(ifaceName)
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

	// Add the route to the interface
	req := &rtnetlink.RouteMessage{
		Family:    uint8(family),
		Table:     unix.RT_TABLE_MAIN,
		Protocol:  unix.RTPROT_BOOT,
		Scope:     unix.RT_SCOPE_LINK,
		Type:      unix.RTN_UNICAST,
		DstLength: uint8(ones),
		Attributes: rtnetlink.RouteAttributes{
			Dst:      addr.Masked().Addr().AsSlice(),
			OutIface: uint32(iface.Index),
		},
	}
	slog.Default().With("route", "add").
		Debug("adding route", slog.Any("request", req))
	err = conn.Route.Add(req)
	if err != nil {
		if strings.Contains(err.Error(), "file exists") {
			return ErrRouteExists
		}
		return fmt.Errorf("add route to interface: %w", err)
	}
	return nil
}

// RemoveRoute removes a route from the interface with the given name.
func RemoveRoute(ctx context.Context, ifaceName string, addr netip.Prefix) error {
	iface, err := net.InterfaceByName(ifaceName)
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

	// Delete the route from the interface
	req := &rtnetlink.RouteMessage{
		Family:    uint8(family),
		Table:     unix.RT_TABLE_MAIN,
		Protocol:  unix.RTPROT_BOOT,
		Scope:     unix.RT_SCOPE_LINK,
		Type:      unix.RTN_UNICAST,
		DstLength: uint8(ones),
		Attributes: rtnetlink.RouteAttributes{
			Dst:      addr.Masked().Addr().AsSlice(),
			OutIface: uint32(iface.Index),
		},
	}
	slog.Default().With("route", "del").
		Debug("removing route", slog.Any("request", req))
	err = conn.Route.Delete(req)
	if err != nil {
		return fmt.Errorf("delete route from interface: %w", err)
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
