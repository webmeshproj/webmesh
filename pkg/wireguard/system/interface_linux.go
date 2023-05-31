/*
Copyright 2023.

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
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/jsimonetti/rtnetlink"
	"golang.org/x/exp/slog"
	"golang.org/x/sys/unix"

	"github.com/webmeshproj/node/pkg/util"
)

// IsRouteExists returns true if the given error is a route exists error.
func IsRouteExists(err error) bool {
	return errors.Is(err, ErrRouteExists)
}

type linuxKernelInterface struct {
	opts *Options
	log  *slog.Logger
}

// New creates a new wireguard interface.
func New(ctx context.Context, opts *Options) (Interface, error) {
	if opts.ForceTUN {
		return NewTUN(ctx, opts)
	}
	logger := slog.Default().With(
		slog.String("component", "wireguard"),
		slog.String("type", "kernel"),
		slog.String("facility", "device"))
	if opts.Modprobe {
		err := util.Modprobe("wireguard", "")
		if err != nil {
			// Try to fallback to TUN
			logger.Error("load wireguard kernel module, falling back to TUN", slog.String("error", err.Error()))
			return NewTUN(ctx, opts)
		}
	}
	if !opts.DefaultGateway.IsValid() {
		defaultGateway, err := util.GetDefaultGateway(ctx)
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

// Name returns the real name of the interface.
func (l *linuxKernelInterface) Name() string {
	return l.opts.Name
}

// AddressV4 should return the current private address of this interface
func (l *linuxKernelInterface) AddressV4() netip.Prefix {
	return l.opts.NetworkV4
}

// AddressV6 should return the current private address of this interface
func (l *linuxKernelInterface) AddressV6() netip.Prefix {
	return l.opts.NetworkV6
}

// Up activates the interface
func (l *linuxKernelInterface) Up(ctx context.Context) error {
	return l.activate(ctx)
}

// Down deactivates the interface
func (l *linuxKernelInterface) Down(ctx context.Context) error {
	return l.deactivate(ctx)
}

// Destroy destroys the interface
func (l *linuxKernelInterface) Destroy(ctx context.Context) error {
	return l.destroy(ctx)
}

// AddRoute adds a route for the given network.
func (l *linuxKernelInterface) AddRoute(ctx context.Context, network netip.Prefix) error {
	return l.addRoute(ctx, network)
}

// RemoveRoute removes the route for the given network.
func (l *linuxKernelInterface) RemoveRoute(ctx context.Context, network netip.Prefix) error {
	return l.removeRoute(ctx, network)
}

func (l *linuxKernelInterface) create(ctx context.Context) error {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	name := l.opts.Name
	req := &rtnetlink.LinkMessage{
		Family: unix.AF_UNSPEC,
		Type:   unix.RTM_NEWLINK,
		Flags: unix.NLM_F_REQUEST |
			unix.NLM_F_ACK |
			unix.NLM_F_EXCL | // fail if already exists
			unix.NLM_F_CREATE, // create if it does not exist
		Attributes: &rtnetlink.LinkAttributes{
			Name:  name,
			Alias: &name,
			Type:  unix.ARPHRD_NETROM,
			Info:  &rtnetlink.LinkInfo{Kind: "wireguard"},
		},
	}
	slog.Default().Debug("creating wireguard interface",
		slog.Any("request", req),
		slog.String("name", name))
	err = conn.Link.New(req)
	if err != nil {
		return fmt.Errorf("create wireguard interface: %w", err)
	}
	for _, addr := range []netip.Prefix{l.opts.NetworkV4, l.opts.NetworkV6} {
		if addr.IsValid() {
			err = l.setAddress(ctx, addr)
			if err != nil {
				derr := l.destroy(ctx)
				if derr != nil {
					return fmt.Errorf("set address %q on wireguard interface: %w, destroy interface: %v", addr.String(), err, derr)
				}
				return fmt.Errorf("set address %q on wireguard interface: %w", addr.String(), err)
			}
		}
	}
	return nil
}

func (l *linuxKernelInterface) destroy(ctx context.Context) error {
	iface, err := net.InterfaceByName(l.opts.Name)
	if err != nil {
		return fmt.Errorf("get interface: %w", err)
	}
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	slog.Default().Debug("destroying wireguard interface", slog.String("name", l.opts.Name))
	err = conn.Link.Delete(uint32(iface.Index))
	if err != nil {
		return fmt.Errorf("delete interface: %w", err)
	}
	return nil
}

func (l *linuxKernelInterface) activate(ctx context.Context) error {
	iface, err := net.InterfaceByName(l.opts.Name)
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

func (l *linuxKernelInterface) deactivate(ctx context.Context) error {
	iface, err := net.InterfaceByName(l.opts.Name)
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

func (l *linuxKernelInterface) addRoute(ctx context.Context, addr netip.Prefix) error {
	iface, err := net.InterfaceByName(l.opts.Name)
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

func (l *linuxKernelInterface) removeRoute(ctx context.Context, addr netip.Prefix) error {
	iface, err := net.InterfaceByName(l.opts.Name)
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

func (l *linuxKernelInterface) setAddress(ctx context.Context, addr netip.Prefix) error {
	iface, err := net.InterfaceByName(l.opts.Name)
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
