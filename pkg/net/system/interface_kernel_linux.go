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

	"github.com/jsimonetti/rtnetlink"
	"golang.org/x/exp/slog"
	"golang.org/x/sys/unix"
	"pault.ag/go/modprobe"
)

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
	return ActivateInterface(ctx, l.opts.Name)
}

// Down deactivates the interface
func (l *linuxKernelInterface) Down(ctx context.Context) error {
	return DeactivateInterface(ctx, l.opts.Name)
}

// Destroy destroys the interface
func (l *linuxKernelInterface) Destroy(ctx context.Context) error {
	return DestroyInterface(ctx, l.opts.Name)
}

// AddRoute adds a route for the given network.
func (l *linuxKernelInterface) AddRoute(ctx context.Context, network netip.Prefix) error {
	return AddRoute(ctx, l.opts.Name, network)
}

// RemoveRoute removes the route for the given network.
func (l *linuxKernelInterface) RemoveRoute(ctx context.Context, network netip.Prefix) error {
	return RemoveRoute(ctx, l.opts.Name, network)
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
			MTU:   l.opts.MTU,
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
			err = SetInterfaceAddress(ctx, l.opts.Name, addr)
			if err != nil {
				derr := DestroyInterface(ctx, l.opts.Name)
				if derr != nil {
					return fmt.Errorf("set address %q on wireguard interface: %w, destroy interface: %v", addr.String(), err, derr)
				}
				return fmt.Errorf("set address %q on wireguard interface: %w", addr.String(), err)
			}
		}
	}
	return nil
}
