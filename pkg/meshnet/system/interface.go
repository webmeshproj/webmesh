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

// Package system contains utilities for managing network interfaces on the system.
package system

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"strings"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system/link"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system/routes"
)

// DefaultMTU is the default MTU for wireguard interfaces.
// TODO: Try to determine this automatically.
const DefaultMTU = 1420

// Interface represents an underlying machine network interface for
// use with WireGuard.
type Interface interface {
	// Name returns the real name of the interface.
	Name() string
	// AddressV4 should return the current private IPv4 address of this interface.
	AddressV4() netip.Prefix
	// AddressV6 should return the current private IPv6 address of this interface.
	AddressV6() netip.Prefix
	// Up activates the interface.https://kind.sigs.k8s.io/
	Up(context.Context) error
	// Down deactivates the interface.
	Down(context.Context) error
	// Destroy destroys the interface.
	Destroy(context.Context) error
	// AddRoute adds a route for the given network.
	AddRoute(context.Context, netip.Prefix) error
	// RemoveRoute removes the route for the given network.
	RemoveRoute(context.Context, netip.Prefix) error
	// Link returns the underlying net.Interface.
	Link() (*net.Interface, error)
	// HardwareAddr returns the hardware address of the interface.
	HardwareAddr() (net.HardwareAddr, error)
}

// Options represents the options for creating a new interface.
type Options struct {
	// Name is the name of the interface.
	Name string
	// NetNs is the network namespace to create the interface in.
	// This is only supported on Linux.
	NetNs string
	// AddressV4 is the private IPv4 network of this interface.
	AddressV4 netip.Prefix
	// AddressV6 is the private IPv6 network of this interface.
	AddressV6 netip.Prefix
	// ForceTUN forces the use of a TUN interface.
	ForceTUN bool
	// MTU is the MTU of the interface. If unset, it will be automatically
	// detected from the host.
	MTU uint32
	// DisableIPv4 disables IPv4 on the interface.
	DisableIPv4 bool
	// DisableIPv6 disables IPv6 on the interface.
	DisableIPv6 bool
}

// IsRouteExists returns true if the given error is a route exists error.
func IsRouteExists(err error) bool {
	return errors.Is(err, routes.ErrRouteExists)
}

// IsInterfaceNotExists returns true if the given error is an interface not exists error.
func IsInterfaceNotExists(err error) bool {
	ok := errors.Is(err, link.ErrLinkNotExists)
	return ok || strings.Contains(err.Error(), "no such network interface")
}

// New creates a new interface using the given options.
func New(ctx context.Context, opts *Options) (Interface, error) {
	if opts.MTU <= 0 {
		opts.MTU = DefaultMTU
	}
	log := context.LoggerFrom(ctx).With(slog.String("component", "wireguard"))
	ctx = context.WithLogger(ctx, log)
	iface := &sysInterface{
		ifname: opts.Name,
		addrv4: opts.AddressV4,
		addrv6: opts.AddressV6,
		netns:  opts.NetNs,
	}
	forceTUN := opts.ForceTUN || (runtime.GOOS != "linux" && runtime.GOOS != "freebsd")
	mtu := opts.MTU
	if forceTUN {
		log.Debug("Creating wireguard tun interface")
		name, closer, err := link.NewTUN(ctx, iface.ifname, mtu)
		if err != nil {
			return nil, fmt.Errorf("new tun: %w", err)
		}
		iface.ifname = name
		iface.close = func(context.Context) error {
			closer()
			return nil
		}
	} else {
		log.Debug("Creating wireguard kernel interface")
		err := link.NewKernel(ctx, iface.ifname, mtu)
		if err != nil {
			log.Error("Failed to create kernel interface failed, falling back to TUN driver", "error", err)
			// Try the TUN device as a fallback
			name, closer, err := link.NewTUN(ctx, iface.ifname, mtu)
			if err != nil {
				return nil, fmt.Errorf("new tun: %w", err)
			}
			iface.ifname = name
			iface.close = func(context.Context) error {
				closer()
				return nil
			}
		} else {
			iface.close = func(ctx context.Context) error {
				return link.RemoveInterface(ctx, iface.ifname)
			}
		}
	}
	if !opts.DisableIPv4 && opts.AddressV4.IsValid() {
		err := iface.setInterfaceAddress(ctx, opts.AddressV4)
		if err != nil {
			derr := iface.close(ctx)
			if derr != nil {
				return nil, fmt.Errorf("%w, destroy interface: %v", err, derr)
			}
			return nil, err
		}
	}
	if !opts.DisableIPv6 && opts.AddressV6.IsValid() {
		err := iface.setInterfaceAddress(ctx, opts.AddressV6)
		if err != nil {
			derr := iface.close(ctx)
			if derr != nil {
				return nil, fmt.Errorf("%w, destroy interface: %v", err, derr)
			}
			return nil, err
		}
	}
	if runtime.GOOS == "linux" && opts.NetNs != "" {
		log.Debug("Moving link into netns", "netns", opts.NetNs)
		err := moveLinkIn(opts.NetNs, iface.ifname)
		if err != nil {
			return nil, fmt.Errorf("failed to move link %q into netns %q: %v", iface.ifname, opts.NetNs, err)
		}
	}
	return iface, nil
}

type sysInterface struct {
	ifname string
	addrv4 netip.Prefix
	addrv6 netip.Prefix
	netns  string
	close  func(context.Context) error
}

func (l *sysInterface) setInterfaceAddress(ctx context.Context, addr netip.Prefix) error {
	// Currently we do this before moving the interface into the netns, so we don't need to
	// do anything special here. But we should eventually support adding addresses to interfaces
	// in other netns's.
	// context.LoggerFrom(ctx).Debug("Setting interface address", "address", addr.String())
	// if runtime.GOOS == "linux" && l.netns != "" {
	// 	return DoInNetNS(l.netns, func() error {
	// 		return link.SetInterfaceAddress(ctx, l.Name(), addr)
	// 	})
	// }
	err := link.SetInterfaceAddress(ctx, l.Name(), addr)
	if err != nil {
		return fmt.Errorf("set address %q on wireguard interface: %w", addr.String(), err)
	}
	return nil
}

// Name returns the real name of the interface.
func (l *sysInterface) Name() string {
	return l.ifname
}

// AddressV4 should return the current private address of this interface.
func (l *sysInterface) AddressV4() netip.Prefix {
	return l.addrv4
}

// AddressV6 should return the current private address of this interface.
func (l *sysInterface) AddressV6() netip.Prefix {
	return l.addrv6
}

// Up activates the interface
func (l *sysInterface) Up(ctx context.Context) error {
	if runtime.GOOS == "linux" && l.netns != "" {
		return DoInNetNS(l.netns, func() error {
			return link.ActivateInterface(ctx, l.Name())
		})
	}
	return link.ActivateInterface(ctx, l.Name())
}

// Down deactivates the interface
func (l *sysInterface) Down(ctx context.Context) error {
	if runtime.GOOS == "linux" && l.netns != "" {
		return DoInNetNS(l.netns, func() error {
			return link.DeactivateInterface(ctx, l.Name())
		})
	}
	return link.DeactivateInterface(ctx, l.Name())
}

// Destroy destroys the interface
func (l *sysInterface) Destroy(ctx context.Context) error {
	if runtime.GOOS == "linux" && l.netns != "" {
		if err := moveLinkOut(l.netns, l.Name()); err != nil {
			return fmt.Errorf("failed to move link out of container namespace: %w", err)
		}
	}
	return l.close(ctx)
}

// AddRoute adds a route for the given network.
func (l *sysInterface) AddRoute(ctx context.Context, network netip.Prefix) error {
	if runtime.GOOS == "linux" && l.netns != "" {
		return DoInNetNS(l.netns, func() error {
			return routes.Add(ctx, l.Name(), network)
		})
	}
	return routes.Add(ctx, l.Name(), network)
}

// RemoveRoute removes the route for the given network.
func (l *sysInterface) RemoveRoute(ctx context.Context, network netip.Prefix) error {
	if runtime.GOOS == "linux" && l.netns != "" {
		return DoInNetNS(l.netns, func() error {
			return routes.Remove(ctx, l.Name(), network)
		})
	}
	return routes.Remove(ctx, l.Name(), network)
}

// Link attempts to return the underling net.Interface.
func (l *sysInterface) Link() (*net.Interface, error) {
	if runtime.GOOS == "linux" && l.netns != "" {
		var link *net.Interface
		var err error
		err = DoInNetNS(l.netns, func() error {
			link, err = net.InterfaceByName(l.Name())
			return err
		})
		if err != nil {
			return nil, err
		}
		return link, nil
	}
	link, err := net.InterfaceByName(l.Name())
	if err != nil {
		return nil, fmt.Errorf("get interface by name: %w", err)
	}
	return link, nil
}

// HardwareAddr attempts to return the hardware address of the interface.
func (l *sysInterface) HardwareAddr() (net.HardwareAddr, error) {
	if runtime.GOOS == "linux" && l.netns != "" {
		var link *net.Interface
		var err error
		err = DoInNetNS(l.netns, func() error {
			link, err = l.Link()
			return err
		})
		if err != nil {
			return nil, err
		}
		return link.HardwareAddr, nil
	}
	link, err := l.Link()
	if err != nil {
		return nil, fmt.Errorf("get interface by name: %w", err)
	}
	return link.HardwareAddr, nil
}
