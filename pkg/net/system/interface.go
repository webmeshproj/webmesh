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
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"

	"golang.org/x/exp/slog"
	"pault.ag/go/modprobe"

	"github.com/webmeshproj/node/pkg/net/system/link"
	"github.com/webmeshproj/node/pkg/net/system/routes"
)

// DefaultMTU is the default MTU for wireguard interfaces.
const DefaultMTU = 1350

// MaxMTU is the maximum MTU for wireguard interfaces.
const MaxMTU = 1500

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
	// NetworkV4 is the private IPv4 network of this interface.
	NetworkV4 netip.Prefix
	// NetworkV6 is the private IPv6 network of this interface.
	NetworkV6 netip.Prefix
	// ForceTUN forces the use of a TUN interface.
	ForceTUN bool
	// Modprobe attempts to load the wireguard kernel module.
	Modprobe bool
	// MTU is the MTU of the interface. If unset, it will be automatically
	// detected from the host.
	MTU uint32
}

// New creates a new interface using the given options.
func New(ctx context.Context, opts *Options) (Interface, error) {
	if opts.MTU == 0 {
		opts.MTU = DefaultMTU
	}
	logger := slog.Default().With(
		slog.String("component", "wireguard"),
		slog.String("facility", "device"))
	if opts.Modprobe {
		err := modprobe.Load("wireguard", "")
		if err != nil {
			// Will attempt a TUN device later on
			logger.Error("load wireguard kernel module", slog.String("error", err.Error()))
		}
	}
	iface := &sysInterface{
		opts: opts,
	}
	useTUN := opts.ForceTUN || (runtime.GOOS != "linux" && runtime.GOOS != "freebsd")
	if useTUN {
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
		err := link.NewKernel(ctx, opts.Name, opts.MTU)
		if err != nil {
			logger.Error("create wireguard kernel interface, attempting TUN interface", "error", err)
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
	for _, addr := range []netip.Prefix{opts.NetworkV4, opts.NetworkV6} {
		if addr.IsValid() {
			err := link.SetInterfaceAddress(ctx, opts.Name, addr)
			if err != nil {
				derr := iface.close(ctx)
				if derr != nil {
					return nil, fmt.Errorf("set address %q on wireguard interface: %w, destroy interface: %v", addr.String(), err, derr)
				}
				return nil, fmt.Errorf("set address %q on wireguard interface: %w", addr.String(), err)
			}
		}
	}
	return iface, nil
}

// IsRouteExists returns true if the given error is a route exists error.
func IsRouteExists(err error) bool {
	return errors.Is(err, routes.ErrRouteExists)
}

// IsInterfaceNotExists returns true if the given error is an interface not exists error.
func IsInterfaceNotExists(err error) bool {
	_, ok := err.(net.UnknownNetworkError)
	return ok || strings.Contains(err.Error(), "no such network interface")
}

type sysInterface struct {
	opts  *Options
	close func(context.Context) error
}

// Name returns the real name of the interface.
func (l *sysInterface) Name() string {
	return l.opts.Name
}

// AddressV4 should return the current private address of this interface
func (l *sysInterface) AddressV4() netip.Prefix {
	return l.opts.NetworkV4
}

// AddressV6 should return the current private address of this interface
func (l *sysInterface) AddressV6() netip.Prefix {
	return l.opts.NetworkV6
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
