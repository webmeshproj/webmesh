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
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/net/system/link"
	"github.com/webmeshproj/node/pkg/net/system/routes"
)

func newInterface(ctx context.Context, opts *Options) (Interface, error) {
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
		return nil, fmt.Errorf("create tun: %w", err)
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
		return nil, fmt.Errorf("open uapi: %w", err)
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
		return nil, fmt.Errorf("listen uapi: %w", err)
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

	iface := &darwinTUNInterface{
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

type darwinTUNInterface struct {
	opts *Options
	log  *slog.Logger
	dev  *device.Device
	uapi net.Listener
}

// Name returns the real name of the interface.
func (l *darwinTUNInterface) Name() string {
	return l.opts.Name
}

// AddressV4 should return the current private address of this interface
func (l *darwinTUNInterface) AddressV4() netip.Prefix {
	return l.opts.NetworkV4
}

// AddressV6 should return the current private address of this interface
func (l *darwinTUNInterface) AddressV6() netip.Prefix {
	return l.opts.NetworkV6
}

// Up activates the interface
func (l *darwinTUNInterface) Up(ctx context.Context) error {
	return link.ActivateInterface(ctx, l.opts.Name)
}

// Down deactivates the interface
func (l *darwinTUNInterface) Down(ctx context.Context) error {
	return link.DeactivateInterface(ctx, l.opts.Name)
}

// Destroy destroys the interface
func (l *darwinTUNInterface) Destroy(ctx context.Context) error {
	l.uapi.Close()
	l.dev.Close()
	// The interface destroys itself when the TUN is closed
	return nil
}

// AddRoute adds a route for the given network.
func (l *darwinTUNInterface) AddRoute(ctx context.Context, network netip.Prefix) error {
	return routes.Add(ctx, l.opts.Name, network)
}

// RemoveRoute removes the route for the given network.
func (l *darwinTUNInterface) RemoveRoute(ctx context.Context, network netip.Prefix) error {
	return routes.Remove(ctx, l.opts.Name, network)
}
