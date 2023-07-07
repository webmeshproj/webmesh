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
	"net/netip"

	"golang.org/x/exp/slog"
	"pault.ag/go/modprobe"

	"github.com/webmeshproj/node/pkg/net/system/link"
	"github.com/webmeshproj/node/pkg/net/system/routes"
)

func newInterface(ctx context.Context, opts *Options) (Interface, error) {
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
	iface := &linuxInterface{
		opts: opts,
		log:  logger,
	}
	if opts.ForceTUN {
		name, closer, err := link.NewTUN(ctx, opts.Name, opts.MTU)
		if err != nil {
			return nil, fmt.Errorf("new tun: %w", err)
		}
		iface.opts.Name = name
		iface.close = func() error {
			closer()
			return nil
		}
	} else {
		err := link.New(ctx, opts.Name, opts.MTU)
		if err != nil {
			logger.Error("create wireguard kernel interface, attempting TUN interface", "error", err)
			// Try the TUN device as a fallback
			name, closer, err := link.NewTUN(ctx, opts.Name, opts.MTU)
			if err != nil {
				return nil, fmt.Errorf("new tun: %w", err)
			}
			iface.opts.Name = name
			iface.close = func() error {
				closer()
				return nil
			}
		} else {
			iface.close = func() error {
				return link.RemoveInterface(ctx, opts.Name)
			}
		}
	}
	for _, addr := range []netip.Prefix{opts.NetworkV4, opts.NetworkV6} {
		if addr.IsValid() {
			err := link.SetInterfaceAddress(ctx, opts.Name, addr)
			if err != nil {
				derr := iface.close()
				if derr != nil {
					return nil, fmt.Errorf("set address %q on wireguard interface: %w, destroy interface: %v", addr.String(), err, derr)
				}
				return nil, fmt.Errorf("set address %q on wireguard interface: %w", addr.String(), err)
			}
		}
	}
	return iface, nil
}

type linuxInterface struct {
	opts  *Options
	log   *slog.Logger
	close func() error
}

// Name returns the real name of the interface.
func (l *linuxInterface) Name() string {
	return l.opts.Name
}

// AddressV4 should return the current private address of this interface
func (l *linuxInterface) AddressV4() netip.Prefix {
	return l.opts.NetworkV4
}

// AddressV6 should return the current private address of this interface
func (l *linuxInterface) AddressV6() netip.Prefix {
	return l.opts.NetworkV6
}

// Up activates the interface
func (l *linuxInterface) Up(ctx context.Context) error {
	return link.ActivateInterface(ctx, l.opts.Name)
}

// Down deactivates the interface
func (l *linuxInterface) Down(ctx context.Context) error {
	return link.DeactivateInterface(ctx, l.opts.Name)
}

// Destroy destroys the interface
func (l *linuxInterface) Destroy(ctx context.Context) error {
	return l.close()
}

// AddRoute adds a route for the given network.
func (l *linuxInterface) AddRoute(ctx context.Context, network netip.Prefix) error {
	return routes.Add(ctx, l.opts.Name, network)
}

// RemoveRoute removes the route for the given network.
func (l *linuxInterface) RemoveRoute(ctx context.Context, network netip.Prefix) error {
	return routes.Remove(ctx, l.opts.Name, network)
}
