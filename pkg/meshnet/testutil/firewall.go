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

import "context"

// Firewall is a mock firewall.
type Firewall struct{}

// AddWireguardForwarding should configure the firewall to allow forwarding traffic on the wireguard interface.
func (fw *Firewall) AddWireguardForwarding(ctx context.Context, ifaceName string) error {
	return nil
}

// AddMasquerade should configure the firewall to masquerade outbound traffic on the wireguard interface.
func (fw *Firewall) AddMasquerade(ctx context.Context, ifaceName string) error {
	return nil
}

// Clear should clear any changes made to the firewall.
func (fw *Firewall) Clear(ctx context.Context) error {
	return nil
}

// Close should close any resources used by the firewall. It should also perform a Clear.
func (fw *Firewall) Close(ctx context.Context) error {
	return nil
}
