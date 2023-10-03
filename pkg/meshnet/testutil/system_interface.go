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

// TestSystemInterface is a test interface for use with testing.
// It implements system.Interface but maintains state in-memory
// and does not make any modifications to the system.
type TestSystemInterface struct {
	*system.Options
	hwaddr  net.HardwareAddr
	started bool
	closed  bool
	routes  []netip.Prefix
	mu      sync.Mutex
}

// NewTestSystemInterface creates a new test interface.
func NewTestSystemInterface(ctx context.Context, opts *system.Options) (system.Interface, error) {
	hwaddr := make([]byte, 6)
	_, err := rand.Read(hwaddr)
	if err != nil {
		return nil, fmt.Errorf("generate random hardware address: %w", err)
	}
	return &TestSystemInterface{
		Options: opts,
		hwaddr:  hwaddr,
	}, nil
}

// Name returns the real name of the interface.
func (t *TestSystemInterface) Name() string {
	return t.Options.Name
}

// AddressV4 should return the current private IPv4 address of this interface.
func (t *TestSystemInterface) AddressV4() netip.Prefix {
	return t.Options.AddressV4
}

// AddressV6 should return the current private IPv6 address of this interface.
func (t *TestSystemInterface) AddressV6() netip.Prefix {
	return t.Options.AddressV6
}

// Up activates the interface.
func (t *TestSystemInterface) Up(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("interface closed")
	}
	t.started = true
	return nil
}

// Down deactivates the interface.
func (t *TestSystemInterface) Down(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("interface closed")
	}
	t.started = false
	return nil
}

// Destroy destroys the interface.
func (t *TestSystemInterface) Destroy(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("interface closed")
	}
	t.closed = true
	return nil
}

// AddRoute adds a route for the given network.
func (t *TestSystemInterface) AddRoute(_ context.Context, route netip.Prefix) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("interface closed")
	}
	t.routes = append(t.routes, route)
	return nil
}

// RemoveRoute removes the route for the given network.
func (t *TestSystemInterface) RemoveRoute(_ context.Context, route netip.Prefix) error {
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
func (t *TestSystemInterface) Link() (*net.Interface, error) {
	return &net.Interface{
		Index:        1,
		MTU:          system.DefaultMTU,
		Name:         t.Options.Name,
		HardwareAddr: t.hwaddr,
	}, nil
}

// HardwareAddr returns the hardware address of the interface.
func (t *TestSystemInterface) HardwareAddr() (net.HardwareAddr, error) {
	return t.hwaddr, nil
}
