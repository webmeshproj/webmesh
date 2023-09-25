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

package routes

import (
	"context"
	"errors"
	"net/netip"
)

// GetDefaultGateway returns the default gateway of the current system.
func GetDefaultGateway(ctx context.Context) (netip.Addr, error) {
	return netip.Addr{}, errors.New("not implemented")
}

// SetDefaultIPv4Gateway sets the default IPv4 gateway for the current system.
func SetDefaultIPv4Gateway(ctx context.Context, gateway netip.Addr) error {
	return errors.New("not implemented")
}

// SetDefaultIPv6Gateway sets the default IPv6 gateway for the current system.
func SetDefaultIPv6Gateway(ctx context.Context, gateway netip.Addr) error {
	return errors.New("not implemented")
}

// Add adds a route to the interface with the given name.
func Add(ctx context.Context, ifaceName string, addr netip.Prefix) error {
	return errors.New("not implemented")
}

// Remove removes a route from the interface with the given name.
func Remove(ctx context.Context, ifaceName string, addr netip.Prefix) error {
	return errors.New("not implemented")
}
