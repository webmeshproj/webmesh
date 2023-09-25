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

package link

import (
	"context"
	"errors"
	"net/netip"
)

// ActivateInterface activates the interface with the given name.
func ActivateInterface(ctx context.Context, name string) error {
	return errors.New("not implemented")
}

// DeactivateInterface deactivates the interface with the given name.
func DeactivateInterface(ctx context.Context, name string) error {
	return errors.New("not implemented")
}

// RemoveInterface removes the given interface.
func RemoveInterface(ctx context.Context, ifaceName string) error {
	return errors.New("not implemented")
}

// InterfaceNetwork returns the network for the given interface and address.
func InterfaceNetwork(ifaceName string, forAddr netip.Addr, ipv6 bool) (netip.Prefix, error) {
	return netip.Prefix{}, errors.New("not implemented")
}
