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

package testutil

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/webmeshproj/webmesh/pkg/meshnet/system"
)

// SystemInterface is a test interface for use with testing.
// It implements system.Interface but maintains state in-memory
// and does not make any modifications to the system.
type SystemInterface struct {
	*system.Options
	hwaddr  net.HardwareAddr
	started bool
	closed  bool
	addrs   []netip.Prefix
	routes  []netip.Prefix
	mu      sync.Mutex
}

// NewSystemInterface creates a new test system interface.
func NewSystemInterface(ctx context.Context, opts *system.Options) (system.Interface, error) {
	hwaddr := make([]byte, 6)
	_, err := rand.Read(hwaddr)
	if err != nil {
		return nil, fmt.Errorf("generate random hardware address: %w", err)
	}
	return &SystemInterface{
		Options: opts,
		hwaddr:  hwaddr,
	}, nil
}

// Name returns the real name of the interface.
func (t *SystemInterface) Name() string {
	return t.Options.Name
}

// AddressV4 should return the current private IPv4 address of this interface.
func (t *SystemInterface) AddressV4() netip.Prefix {
	if t.Options.DisableIPv4 {
		return netip.Prefix{}
	}
	return t.Options.AddressV4
}

// AddressV6 should return the current private IPv6 address of this interface.
func (t *SystemInterface) AddressV6() netip.Prefix {
	if t.Options.DisableIPv6 {
		return netip.Prefix{}
	}
	return t.Options.AddressV6
}

// Up activates the interface.
func (t *SystemInterface) Up(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("interface closed")
	}
	t.started = true
	return nil
}

// Down deactivates the interface.
func (t *SystemInterface) Down(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("interface closed")
	}
	t.started = false
	return nil
}

// Destroy destroys the interface.
func (t *SystemInterface) Destroy(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("interface closed")
	}
	t.closed = true
	return nil
}

// AddAddress adds an address to the interface.
func (t *SystemInterface) AddAddress(_ context.Context, addr netip.Prefix) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("interface closed")
	}
	if t.Options.DisableIPv4 && addr.Addr().Is4() {
		return nil
	}
	if t.Options.DisableIPv6 && addr.Addr().Is6() {
		return nil
	}
	t.addrs = append(t.addrs, addr)
	return nil
}

// RemoveAddress removes an address from the interface.
func (t *SystemInterface) RemoveAddress(_ context.Context, addr netip.Prefix) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("interface closed")
	}
	for i, a := range t.addrs {
		if a == addr {
			t.addrs = append(t.addrs[:i], t.addrs[i+1:]...)
			break
		}
	}
	return nil
}

// AddRoute adds a route for the given network.
func (t *SystemInterface) AddRoute(_ context.Context, route netip.Prefix) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("interface closed")
	}
	if t.Options.DisableIPv4 && route.Addr().Is4() {
		return nil
	}
	if t.Options.DisableIPv6 && route.Addr().Is6() {
		return nil
	}
	t.routes = append(t.routes, route)
	return nil
}

// RemoveRoute removes the route for the given network.
func (t *SystemInterface) RemoveRoute(_ context.Context, route netip.Prefix) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("interface closed")
	}
	for i, r := range t.routes {
		if r == route {
			t.routes = append(t.routes[:i], t.routes[i+1:]...)
			break
		}
	}
	return nil
}

// Link returns the underlying net.Interface.
func (t *SystemInterface) Link() (*net.Interface, error) {
	return &net.Interface{
		Index:        1,
		MTU:          system.DefaultMTU,
		Name:         t.Options.Name,
		HardwareAddr: t.hwaddr,
	}, nil
}

// HardwareAddr returns the hardware address of the interface.
func (t *SystemInterface) HardwareAddr() (net.HardwareAddr, error) {
	return t.hwaddr, nil
}
