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

package firewall

import (
	"context"
	"fmt"
	"net"

	"github.com/webmeshproj/webmesh/pkg/common"
)

func newFirewall(ctx context.Context, opts *Options) (Firewall, error) {
	return &winFirewall{}, nil
}

type winFirewall struct {
}

// AddWireguardForwarding should configure the firewall to allow forwarding traffic on the wireguard interface.
func (wf *winFirewall) AddWireguardForwarding(ctx context.Context, ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return err
	}
	index := iface.Index
	err = common.Exec(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
		`name="WireGuard Forwarding"`, "dir=in", "action=allow",
		fmt.Sprintf("interface=%d", index),
	)
	if err != nil {
		return err
	}
	return nil
}

// AddMasquerade should configure the firewall to masquerade outbound traffic on the wireguard interface.
func (wf *winFirewall) AddMasquerade(ctx context.Context, ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return err
	}
	index := iface.Index
	err = common.Exec(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
		`name="WireGuard Masquerade"`, "dir=out", "action=allow",
		fmt.Sprintf("interface=%d", index),
	)
	if err != nil {
		return err
	}
	return nil
}

// Clear should clear any changes made to the firewall.
func (wf *winFirewall) Clear(ctx context.Context) error {
	// No-op for now, but we may want to add a way to remove the rules we added.
	return nil
}

// Close should close any resources used by the firewall. It should also perform a Clear.
func (wf *winFirewall) Close(ctx context.Context) error {
	// No-op for now, but we may want to add a way to remove the rules we added.
	return nil
}
