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
	"errors"
	"net/netip"
)

// EnableIPForwarding enables IP forwarding.
func EnableIPForwarding() error {
	return errors.New("not implemented")
}

// RemoveInterface removes the given interface.
func RemoveInterface(ifaceName string) error {
	return errors.New("not implemented")
}

// GetDefaultGateway returns the default gateway of the current system.
func GetDefaultGateway(ctx context.Context) (netip.Addr, error) {
	return netip.Addr{}, errors.New("not implemented")
}

// ActivateInterface activates the interface with the given name.
func ActivateInterface(ctx context.Context, name string) error {
	return errors.New("not implemented")
}

// DeactivateInterface deactivates the interface with the given name.
func DeactivateInterface(ctx context.Context, name string) error {
	return errors.New("not implemented")
}

// DestroyInterface destroys the interface with the given name.
func DestroyInterface(ctx context.Context, name string) error {
	return errors.New("not implemented")
}

// SetInterfaceAddress sets the address of the interface with the given name.
func SetInterfaceAddress(ctx context.Context, name string, addr netip.Prefix) error {
	return errors.New("not implemented")
}

// AddRoute adds a route to the interface with the given name.
func AddRoute(ctx context.Context, ifaceName string, addr netip.Prefix) error {
	return errors.New("not implemented")
}

// RemoveRoute removes a route from the interface with the given name.
func RemoveRoute(ctx context.Context, ifaceName string, addr netip.Prefix) error {
	return errors.New("not implemented")
}
