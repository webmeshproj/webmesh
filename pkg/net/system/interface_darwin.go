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
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/util"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

func newInterface(ctx context.Context, opts *Options) (Interface, error) {
	logger := slog.Default().With(
		slog.String("component", "wireguard"),
		slog.String("type", "tun"),
		slog.String("facility", "device"))
	if !opts.DefaultGateway.IsValid() {
		defaultGateway, err := GetDefaultGateway(ctx)
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

	iface := &darwinTUNInterface{
		opts: opts,
		log:  logger,
		dev:  device,
		uapi: uapi,
	}
	for _, addr := range []netip.Prefix{opts.NetworkV4, opts.NetworkV6} {
		if addr.IsValid() {
			err = SetInterfaceAddress(ctx, opts.Name, addr)
			if err != nil {
				iface.uapi.Close()
				iface.dev.Close()
				return nil, fmt.Errorf("set address %q on wireguard interface: %w", addr.String(), err)
			}
		}
	}
	return iface, nil
}

// EnableIPForwarding enables IP forwarding.
func EnableIPForwarding() error {
	return util.Exec(context.Background(), "sysctl", "-w", "net.inet.ip.forwarding=1")
}

// RemoveInterface removes the given interface.
func RemoveInterface(ifaceName string) error {
	return util.Exec(context.Background(), "ifconfig", ifaceName, "destroy")
}

// GetDefaultGateway returns the default gateway of the current system.
func GetDefaultGateway(ctx context.Context) (netip.Addr, error) {
	out, err := util.ExecOutput(ctx, "route", "-n", "get", "default")
	if err != nil {
		return netip.Addr{}, fmt.Errorf("failed to get default gateway: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			return netip.ParseAddr(strings.TrimSpace(line[8:]))
		}
	}
	return netip.Addr{}, errors.New("no default gateway found")
}

// ActivateInterface activates the interface with the given name.
func ActivateInterface(ctx context.Context, name string) error {
	return util.Exec(ctx, "ifconfig", name, "up")
}

// DeactivateInterface deactivates the interface with the given name.
func DeactivateInterface(ctx context.Context, name string) error {
	return util.Exec(ctx, "ifconfig", name, "down")
}

// DestroyInterface destroys the interface with the given name.
func DestroyInterface(ctx context.Context, name string) error {
	return util.Exec(ctx, "ifconfig", name, "destroy")
}

// SetInterfaceAddress sets the address of the interface with the given name.
func SetInterfaceAddress(ctx context.Context, name string, addr netip.Prefix) error {
	return util.Exec(ctx, "ifconfig", name, "inet", addr.String())
}

// AddRoute adds a route to the interface with the given name.
func AddRoute(ctx context.Context, ifaceName string, addr netip.Prefix) error {
	return util.Exec(ctx, "route", "-n", "add", "-net", addr.String(), "-interface", ifaceName)
}

// RemoveRoute removes a route from the interface with the given name.
func RemoveRoute(ctx context.Context, ifaceName string, addr netip.Prefix) error {
	return util.Exec(ctx, "route", "-n", "delete", "-net", addr.String(), "-interface", ifaceName)
}
