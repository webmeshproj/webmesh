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
	"net"
	"net/netip"
	"strings"

	"github.com/jsimonetti/rtnetlink"
	"github.com/vishvananda/netlink"
	"golang.org/x/exp/slog"
	"golang.org/x/sys/unix"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// ActivateInterface activates the interface with the given name.
func ActivateInterface(ctx context.Context, name string) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		if isNoSuchInterfaceErr(err) {
			return ErrLinkNotExists
		}
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
	context.LoggerFrom(ctx).Debug("set interface up", slog.Any("request", req), slog.String("interface", iface.Name))
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
		if isNoSuchInterfaceErr(err) {
			return ErrLinkNotExists
		}
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
	context.LoggerFrom(ctx).Debug("deactivate interface", slog.Any("request", req))
	err = conn.Link.Set(req)
	if err != nil {
		return fmt.Errorf("set interface down: %w", err)
	}
	return nil
}

// RemoveInterface removes the given interface.
func RemoveInterface(ctx context.Context, ifaceName string) error {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		if isNoSuchInterfaceErr(err) {
			return ErrLinkNotExists
		}
		return fmt.Errorf("failed to get interface: %w", err)
	}
	context.LoggerFrom(ctx).Debug("remove interface", slog.String("interface", iface.Name))
	return conn.Link.Delete(uint32(iface.Index))
}

// InterfaceNetwork returns the network for the given interface and address.
func InterfaceNetwork(ifaceName string, forAddr netip.Addr, ipv6 bool) (netip.Prefix, error) {
	family := netlink.FAMILY_V4
	if ipv6 {
		family = netlink.FAMILY_V6
	}
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return netip.Prefix{}, ErrLinkNotExists
		}
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

func isNoSuchInterfaceErr(err error) bool {
	opError := &net.OpError{}
	ok := errors.As(err, &opError)
	return ok && strings.Contains(opError.Unwrap().Error(), "no such network interface")
}
