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
	"fmt"
	"net"

	"github.com/webmeshproj/webmesh/pkg/common"
	"github.com/webmeshproj/webmesh/pkg/context"
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
	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}
	for _, addrnet := range addrs {
		addr, ok := addrnet.(*net.IPNet)
		if !ok {
			continue
		}
		err = common.Exec(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
			`name="webmesh-forward-inbound"`, "dir=in", "action=allow",
			fmt.Sprintf("localip=%s", addr.IP.String()),
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// AddMasquerade should configure the firewall to masquerade outbound traffic on the wireguard interface.
func (wf *winFirewall) AddMasquerade(ctx context.Context, ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}
	for _, addrnet := range addrs {
		addr, ok := addrnet.(*net.IPNet)
		if !ok {
			continue
		}
		err = common.Exec(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
			`name="webmesh-forward-outbound"`, "dir=out", "action=allow",
			fmt.Sprintf("localip=%s", addr.IP.String()),
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// Clear should clear any changes made to the firewall.
func (wf *winFirewall) Clear(ctx context.Context) error {
	for _, name := range []string{"webmesh-forward-inbound", "webmesh-forward-outbound"} {
		err := common.Exec(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", fmt.Sprintf(`name="%s"`, name))
		if err != nil {
			context.LoggerFrom(ctx).Debug("Failed to delete firewall rule", "error", err.Error())
		}
	}
	return nil
}

// Close should close any resources used by the firewall. It should also perform a Clear.
func (wf *winFirewall) Close(ctx context.Context) error {
	// No-op for now, but we may want to add a way to remove the rules we added.
	return wf.Clear(ctx)
}
