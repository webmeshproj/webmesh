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
	"os"
	"strings"

	"github.com/webmeshproj/webmesh/pkg/common"
)

const anchorFile = "/etc/pf.anchors/com.webmesh"

func newFirewall(ctx context.Context, opts *Options) (Firewall, error) {
	// Make sure we can touch the anchor file
	afile := anchorFile
	if opts.ID != "" {
		afile = fmt.Sprintf("%s.%s", anchorFile, opts.ID)
	}
	err := os.WriteFile(afile, []byte{}, 0644)
	if err != nil {
		return nil, fmt.Errorf("touch anchor file: %w", err)
	}
	// Enable the packet filter
	out, err := common.ExecOutput(context.Background(), "pfctl", "-e")
	if err != nil {
		if strings.Contains(err.Error(), "pf already enabled") {
			return &pfctlFirewall{
				enabledAtStart: true,
				anchorFile:     afile,
			}, nil
		}
		return nil, fmt.Errorf("enable pfctl: %w", err)
	}
	return &pfctlFirewall{
		enabledAtStart: false,
		anchorFile:     afile,
	}, nil
}

type pfctlFirewall struct {
	enabledAtStart bool
	anchorFile     string
}

// AddWireguardForwarding should configure the firewall to allow forwarding traffic on the wireguard interface.
func (pf *pfctlFirewall) AddWireguardForwarding(ctx context.Context, ifaceName string) error {
	f, err := os.OpenFile(pf.anchorFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open anchor file: %w", err)
	}
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf("pass in on %s\n", ifaceName))
	if err != nil {
		return fmt.Errorf("write anchor file: %w", err)
	}
	// Reload pfctl
	err = common.Exec(ctx, "pfctl", "-f", anchorFile)
	return err
}

// AddMasquerade should configure the firewall to masquerade outbound traffic on the wireguard interface.
func (pf *pfctlFirewall) AddMasquerade(ctx context.Context, ifaceName string) error {
	f, err := os.OpenFile(pf.anchorFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open anchor file: %w", err)
	}
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf("nat on %s from (%s:network) to any -> (%s:0)\n", ifaceName, ifaceName, ifaceName))
	if err != nil {
		return fmt.Errorf("write anchor file: %w", err)
	}
	// Reload pfctl
	err = common.Exec(ctx, "pfctl", "-f", anchorFile)
	return err
}

// Clear should clear any changes made to the firewall.
func (pf *pfctlFirewall) Clear(ctx context.Context) error {
	// Clear the anchor file
	err := os.WriteFile(pf.anchorFile, []byte{}, 0644)
	if err != nil {
		return fmt.Errorf("clear anchor file: %w", err)
	}
	// Reload pfctl
	err = common.Exec(ctx, "pfctl", "-f", anchorFile)
	return err
}

// Close should close any resources used by the firewall. It should also perform a Clear.
func (pf *pfctlFirewall) Close(ctx context.Context) error {
	err := pf.Clear(ctx)
	if err != nil {
		return fmt.Errorf("clear: %w", err)
	}
	err = os.Remove(pf.anchorFile)
	if err != nil {
		return fmt.Errorf("remove anchor file: %w", err)
	}
	// If we started with pf disabled, re-disable it
	if !pf.enabledAtStart {
		return common.Exec(ctx, "pfctl", "-d")
	}
	// Reload the main pf.conf
	return common.Exec(ctx, "pfctl", "-f", "/etc/pf.conf")
}
