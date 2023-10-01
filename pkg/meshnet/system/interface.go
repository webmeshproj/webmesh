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
// use with wireguard.
type Interface interface {
	// Name returns the real name of the interface.
	Name() string
	// AddressV4 should return the current private IPv4 address of this interface.
	AddressV4() netip.Prefix
	// AddressV6 should return the current private IPv6 address of this interface.
	AddressV6() netip.Prefix
	// Up activates the interface.
	Up(context.Context) error
	// Down deactivates the interface.
	Down(context.Context) error
	// Destroy destroys the interface.
	Destroy(context.Context) error
	// AddRoute adds a route for the given network.
	AddRoute(context.Context, netip.Prefix) error
	// RemoveRoute removes the route for the given network.
	RemoveRoute(context.Context, netip.Prefix) error
}

// Options represents the options for creating a new interface.
type Options struct {
	// Name is the name of the interface.
	Name string
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
	if opts.MTU == 0 {
		opts.MTU = DefaultMTU
	}
	log := context.LoggerFrom(ctx).With(slog.String("component", "wireguard"))
	ctx = context.WithLogger(ctx, log)
	iface := &sysInterface{
		opts: opts,
	}
	forceTUN := opts.ForceTUN || (runtime.GOOS != "linux" && runtime.GOOS != "freebsd")
	if forceTUN {
		log.Debug("creating wireguard tun interface")
		name, closer, err := link.NewTUN(ctx, opts.Name, opts.MTU)
		if err != nil {
			return nil, fmt.Errorf("new tun: %w", err)
		}
		iface.opts.Name = name
		iface.close = func(context.Context) error {
			closer()
			return nil
		}
	} else {
		log.Debug("creating wireguard kernel interface")
		err := link.NewKernel(ctx, opts.Name, opts.MTU)
		if err != nil {
			log.Error("create wireguard kernel interface failed, falling back to TUN interface", "error", err)
			// Try the TUN device as a fallback
			name, closer, err := link.NewTUN(ctx, opts.Name, opts.MTU)
			if err != nil {
				return nil, fmt.Errorf("new tun: %w", err)
			}
			iface.opts.Name = name
			iface.close = func(context.Context) error {
				closer()
				return nil
			}
		} else {
			iface.close = func(ctx context.Context) error {
				return link.RemoveInterface(ctx, opts.Name)
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
	return iface, nil
}

type sysInterface struct {
	opts  *Options
	close func(context.Context) error
}

func (l *sysInterface) setInterfaceAddress(ctx context.Context, addr netip.Prefix) error {
	context.LoggerFrom(ctx).Debug("setting interface address", "address", addr.String())
	err := link.SetInterfaceAddress(ctx, l.opts.Name, addr)
	if err != nil {
		return fmt.Errorf("set address %q on wireguard interface: %w", addr.String(), err)
	}
	return nil
}

// Name returns the real name of the interface.
func (l *sysInterface) Name() string {
	return l.opts.Name
}

// AddressV4 should return the current private address of this interface.
func (l *sysInterface) AddressV4() netip.Prefix {
	return l.opts.AddressV4
}

// AddressV6 should return the current private address of this interface.
func (l *sysInterface) AddressV6() netip.Prefix {
	return l.opts.AddressV6
}

// Up activates the interface
func (l *sysInterface) Up(ctx context.Context) error {
	return link.ActivateInterface(ctx, l.opts.Name)
}

// Down deactivates the interface
func (l *sysInterface) Down(ctx context.Context) error {
	return link.DeactivateInterface(ctx, l.opts.Name)
}

// Destroy destroys the interface
func (l *sysInterface) Destroy(ctx context.Context) error {
	return l.close(ctx)
}

// AddRoute adds a route for the given network.
func (l *sysInterface) AddRoute(ctx context.Context, network netip.Prefix) error {
	return routes.Add(ctx, l.opts.Name, network)
}

// RemoveRoute removes the route for the given network.
func (l *sysInterface) RemoveRoute(ctx context.Context, network netip.Prefix) error {
	return routes.Remove(ctx, l.opts.Name, network)
}

// Interface attempts to return the underling net.Interface.
func (l *sysInterface) Interface() (*net.Interface, error) {
	link, err := net.InterfaceByName(l.opts.Name)
	if err != nil {
		return nil, fmt.Errorf("get interface by name: %w", err)
	}
	return link, nil
}

// HardwareAddr attempts to return the hardware address of the interface.
func (l *sysInterface) HardwareAddr() (net.HardwareAddr, error) {
	link, err := l.Interface()
	if err != nil {
		return nil, fmt.Errorf("get interface by name: %w", err)
	}
	return link.HardwareAddr, nil
}
