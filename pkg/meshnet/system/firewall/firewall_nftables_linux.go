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
	"strings"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/sbezverk/nftableslib"
)

// firewall is a firewall manager that uses nftables.
type firewall struct {
	opts *Options
	conn *nftables.Conn
	ns   ns.NetNS
	// nftables interfaces
	ti           nftableslib.TableFuncs
	natchains    nftableslib.ChainFuncs
	filterchains nftableslib.ChainFuncs
	rawchains    nftableslib.ChainFuncs
	// nat chains
	prerouting  nftableslib.RulesInterface
	postrouting nftableslib.RulesInterface
	output      nftableslib.RulesInterface
	// filter chains
	input   nftableslib.RulesInterface
	forward nftableslib.RulesInterface
	// raw chains
	rawprerouting nftableslib.RulesInterface
}

// newFirewall returns a new nftables firewall manager.
func newFirewall(ctx context.Context, opts *Options) (Firewall, error) {
	fw := &firewall{opts: opts}
	// Initialize a long lasting connection to the nftables library
	var netns []int
	if opts.NetNs != "" {
		ns, err := ns.GetNS(opts.NetNs)
		if err != nil {
			return nil, fmt.Errorf("failed to get netns: %w", err)
		}
		netns = []int{int(ns.Fd())}
		fw.ns = ns
	}
	// Initialize tables
	fw.conn = nftableslib.InitConn(netns...)
	err := fw.initialize(opts)
	if err != nil {
		if strings.Contains(err.Error(), "not supported") || strings.Contains(err.Error(), "no such file") {
			// Try to fallback to iptables
			return newIPTablesFirewall(ctx, opts)
		}
		return nil, err
	}
	return fw, nil
}

// AddWireguardForwarding should configure the firewall to allow forwarding traffic on the wireguard interface.
func (fw *firewall) AddWireguardForwarding(ctx context.Context, ifaceName string) error {
	if len(ifaceName) > 15 {
		ifaceName = ifaceName[:15]
	}
	accept, err := nftableslib.SetVerdict(nftableslib.NFT_ACCEPT)
	if err != nil {
		return fmt.Errorf("failed to create accept verdict: %w", err)
	}
	_, err = fw.forward.Rules().InsertImm(&nftableslib.Rule{
		Meta: &nftableslib.Meta{
			Expr: []nftableslib.MetaExpr{
				{
					Key:   uint32(expr.MetaKeyOIFNAME),
					Value: []byte(ifaceName),
				},
			},
		},
		Action:   accept,
		UserData: nftableslib.MakeRuleComment("Allow forwarding traffic on the wireguard interface"),
	})
	if err != nil {
		return fmt.Errorf("failed to create wireguard forwarding rule: %w", err)
	}
	return fw.conn.Flush()
}

// AddMasquerade should configure the firewall to masquerade outbound traffic on the wireguard interface.
func (fw *firewall) AddMasquerade(ctx context.Context, ifaceName string) error {
	if len(ifaceName) > 15 {
		ifaceName = ifaceName[:15]
	}
	// Masquearade outbound traffic from the wireguard interface
	masq, err := nftableslib.SetMasq(false, false, false)
	if err != nil {
		return fmt.Errorf("failed to create masquerade verdict: %w", err)
	}
	_, err = fw.postrouting.Rules().InsertImm(&nftableslib.Rule{
		Meta: &nftableslib.Meta{
			Expr: []nftableslib.MetaExpr{
				{
					Key:   uint32(expr.MetaKeyOIFNAME),
					Value: []byte(ifaceName),
				},
			},
		},
		Action:   masq,
		UserData: nftableslib.MakeRuleComment("Masquerade outbound traffic on the wireguard interface"),
	})
	if err != nil {
		return fmt.Errorf("failed to create outbound wireguard masquerade rule: %w", err)
	}
	// Masquearade inbound traffic from the wireguard interface
	_, err = fw.postrouting.Rules().InsertImm(&nftableslib.Rule{
		Meta: &nftableslib.Meta{
			Expr: []nftableslib.MetaExpr{
				{
					Key:   uint32(expr.MetaKeyIIFNAME),
					Value: []byte(ifaceName),
				},
			},
		},
		Action:   masq,
		UserData: nftableslib.MakeRuleComment("Masquerade inbound traffic on the wireguard interface"),
	})
	if err != nil {
		return fmt.Errorf("failed to create inbound wireguard masquerade rule: %w", err)
	}
	return fw.conn.Flush()
}

// Clear should clear any changes made to the firewall.
func (fw *firewall) Clear(ctx context.Context) error {
	for _, table := range []string{inetNatTable, inetFilterTable, inetRawTable} {
		err := fw.ti.DeleteImm(table, nftables.TableFamilyINet)
		if err != nil {
			return fmt.Errorf("failed to delete inet %s table: %w", table, err)
		}
	}
	return fw.conn.Flush()
}

// Close should close any resources used by the firewall. It should also
// call Clear.
func (fw *firewall) Close(ctx context.Context) error {
	err := fw.Clear(ctx)
	if err != nil {
		return fmt.Errorf("failed to clear firewall: %w", err)
	}
	if fw.ns != nil {
		defer fw.ns.Close()
	}
	return fw.conn.CloseLasting()
}
