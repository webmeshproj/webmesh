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
	"context"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"pault.ag/go/modprobe"

	"github.com/webmeshproj/node/pkg/net/system/link"
	"github.com/webmeshproj/node/pkg/net/system/routes"
)

func newInterface(ctx context.Context, opts *Options) (Interface, error) {
	if opts.MTU == 0 {
		opts.MTU = DefaultMTU
	}
	if opts.ForceTUN {
		return newTUN(ctx, opts)
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
			return newTUN(ctx, opts)
		}
	}
	if !opts.DefaultGateway.IsValid() {
		defaultGateway, err := routes.GetDefaultGateway(ctx)
		if err != nil {
			return nil, fmt.Errorf("detect current default gateway")
		}
		opts.DefaultGateway = defaultGateway
	}
	iface := &linuxKernelInterface{
		opts: opts,
		log:  logger,
	}
	err := link.New(ctx, opts.Name, opts.MTU)
	for _, addr := range []netip.Prefix{opts.NetworkV4, opts.NetworkV6} {
		if addr.IsValid() {
			err = link.SetInterfaceAddress(ctx, opts.Name, addr)
			if err != nil {
				derr := link.RemoveInterface(ctx, opts.Name)
				if derr != nil {
					return nil, fmt.Errorf("set address %q on wireguard interface: %w, destroy interface: %v", addr.String(), err, derr)
				}
				return nil, fmt.Errorf("set address %q on wireguard interface: %w", addr.String(), err)
			}
		}
	}
	return iface, nil
}

type linuxKernelInterface struct {
	opts *Options
	log  *slog.Logger
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
	return link.ActivateInterface(ctx, l.opts.Name)
}

// Down deactivates the interface
func (l *linuxKernelInterface) Down(ctx context.Context) error {
	return link.DeactivateInterface(ctx, l.opts.Name)
}

// Destroy destroys the interface
func (l *linuxKernelInterface) Destroy(ctx context.Context) error {
	return link.RemoveInterface(ctx, l.opts.Name)
}

// AddRoute adds a route for the given network.
func (l *linuxKernelInterface) AddRoute(ctx context.Context, network netip.Prefix) error {
	return routes.Add(ctx, l.opts.Name, network)
}

// RemoveRoute removes the route for the given network.
func (l *linuxKernelInterface) RemoveRoute(ctx context.Context, network netip.Prefix) error {
	return routes.Remove(ctx, l.opts.Name, network)
}

type linuxTUNInterface struct {
	opts *Options
	log  *slog.Logger
	dev  *device.Device
	uapi net.Listener
}

// NewTUN creates a new wireguard interface using the userspace TUN implementation.
func newTUN(ctx context.Context, opts *Options) (Interface, error) {
	logger := slog.Default().With(
		slog.String("component", "wireguard"),
		slog.String("type", "tun"),
		slog.String("facility", "device"))
	if !opts.DefaultGateway.IsValid() {
		defaultGateway, err := routes.GetDefaultGateway(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to detect current default gateway")
		}
		opts.DefaultGateway = defaultGateway
	}

	// Create the TUN device
	tun, err := tun.CreateTUN(opts.Name, device.DefaultMTU)
	if err != nil {
		return nil, err
	}
	// Get the real name of the interface
	realName, err := tun.Name()
	if err == nil {
		opts.Name = realName
	}

	// Open the UAPI socket
	fileuapi, err := ipc.UAPIOpen(opts.Name)
	if err != nil {
		tun.Close()
		return nil, err
	}

	// Create the tunnel device
	device := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(
		func() int {
			if logger.Handler().Enabled(context.Background(), slog.LevelDebug) {
				return device.LogLevelVerbose
			}
			return device.LogLevelError
		}(),
		fmt.Sprintf("(%s) ", opts.Name),
	))

	// Listen for UAPI connections
	uapi, err := ipc.UAPIListen(opts.Name, fileuapi)
	if err != nil {
		device.Close()
		return nil, err
	}

	// Handle UAPI connections
	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				return
			}
			go device.IpcHandle(conn)
		}
	}()

	iface := &linuxTUNInterface{
		opts: opts,
		log:  logger,
		dev:  device,
		uapi: uapi,
	}
	for _, addr := range []netip.Prefix{opts.NetworkV4, opts.NetworkV6} {
		if addr.IsValid() {
			err = link.SetInterfaceAddress(ctx, opts.Name, addr)
			if err != nil {
				iface.uapi.Close()
				iface.dev.Close()
				return nil, fmt.Errorf("set address %q on wireguard interface: %w", addr.String(), err)
			}
		}
	}
	return iface, nil
}

// Name returns the real name of the interface.
func (l *linuxTUNInterface) Name() string {
	return l.opts.Name
}

// AddressV4 should return the current private address of this interface
func (l *linuxTUNInterface) AddressV4() netip.Prefix {
	return l.opts.NetworkV4
}

// AddressV6 should return the current private address of this interface
func (l *linuxTUNInterface) AddressV6() netip.Prefix {
	return l.opts.NetworkV6
}

// Up activates the interface
func (l *linuxTUNInterface) Up(ctx context.Context) error {
	return link.ActivateInterface(ctx, l.opts.Name)
}

// Down deactivates the interface
func (l *linuxTUNInterface) Down(ctx context.Context) error {
	return link.DeactivateInterface(ctx, l.opts.Name)
}

// Destroy destroys the interface
func (l *linuxTUNInterface) Destroy(ctx context.Context) error {
	l.uapi.Close()
	l.dev.Close()
	// The interface destroys itself when the TUN is closed
	return nil
}

// AddRoute adds a route for the given network.
func (l *linuxTUNInterface) AddRoute(ctx context.Context, network netip.Prefix) error {
	return routes.Add(ctx, l.opts.Name, network)
}

// RemoveRoute removes the route for the given network.
func (l *linuxTUNInterface) RemoveRoute(ctx context.Context, network netip.Prefix) error {
	return routes.Remove(ctx, l.opts.Name, network)
}
