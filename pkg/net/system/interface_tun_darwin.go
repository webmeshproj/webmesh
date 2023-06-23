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
	"net"
	"net/netip"

	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/device"
)

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
	return ActivateInterface(ctx, l.opts.Name)
}

// Down deactivates the interface
func (l *darwinTUNInterface) Down(ctx context.Context) error {
	return DeactivateInterface(ctx, l.opts.Name)
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
	return AddRoute(ctx, l.opts.Name, network)
}

// RemoveRoute removes the route for the given network.
func (l *darwinTUNInterface) RemoveRoute(ctx context.Context, network netip.Prefix) error {
	return RemoveRoute(ctx, l.opts.Name, network)
}
