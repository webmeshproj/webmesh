/*
Copyright 2023.

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
	"os/exec"
	"strings"

	"golang.org/x/exp/slog"
)

func newIPTablesFirewall(opts *Options) (Firewall, error) {
	fw := &iptablesFirewall{
		log: slog.Default().With(slog.String("component", "iptables-firewall")),
	}
	return fw, nil
}

type iptablesFirewall struct {
	log *slog.Logger
}

// AddWireguardForwarding should configure the firewall to allow forwarding traffic on the wireguard interface.
func (fw *iptablesFirewall) AddWireguardForwarding(ctx context.Context, ifaceName string) error {
	return fw.exec(ctx, "-A", "FORWARD", "-i", ifaceName, "-j", "ACCEPT")
}

// AddMasquerade should configure the firewall to masquerade outbound traffic on the wireguard interface.
func (fw *iptablesFirewall) AddMasquerade(ctx context.Context, ifaceName string) error {
	return fw.exec(ctx, "-t", "nat", "-A", "POSTROUTING", "-o", ifaceName, "-j", "MASQUERADE")
}

// Clear should clear any changes made to the firewall.
func (fw *iptablesFirewall) Clear(ctx context.Context) error {
	return fw.exec(ctx, "-F")
}

// Close should close any resources used by the firewall. It should also perform a Clear.
func (fw *iptablesFirewall) Close(ctx context.Context) error {
	return fw.Clear(ctx)
}

func (fw *iptablesFirewall) exec(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "iptables", args...)
	fw.log.Debug("iptables", slog.String("args", strings.Join(args, " ")))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables %v: %v: %s", args, err, out)
	}
	return nil
}
