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
	"encoding/binary"
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/sbezverk/nftableslib"
	"golang.org/x/sys/unix"
)

const (
	// Table Names
	inetFilterTable = "meshfilter"
	inetNatTable    = "meshnat"
	inetRawTable    = "meshraw"
	// Raw Chains
	inetRawPrerouting = "prerouting"
	// NAT Chains
	inetPostRoutingChain = "postrouting"
	inetPreroutingChain  = "prerouting"
	inetOutputChain      = "output"
	// Filter Chains
	inetInputChain   = "input"
	inetForwardChain = "forward"
)

func (fw *firewall) initialize(opts *Options) error {
	var err error
	for _, f := range []func() error{
		func() error { return fw.initTables(opts) },
		fw.initChains,
		fw.initInputChain,
	} {
		if err = f(); err != nil {
			return err
		}
	}
	return fw.conn.Flush()
}

func (fw *firewall) initTables(opts *Options) error {
	filterTable := inetFilterTable
	natTable := inetNatTable
	rawTable := inetRawTable
	if opts.ID != "" {
		filterTable = fmt.Sprintf("%s_%s", inetFilterTable, opts.ID)
		natTable = fmt.Sprintf("%s_%s", inetNatTable, opts.ID)
		rawTable = fmt.Sprintf("%s_%s", inetRawTable, opts.ID)
	}
	tablesNames := []string{filterTable, natTable, rawTable}
	fw.ti = nftableslib.InitNFTables(fw.conn).Tables()
	for _, table := range tablesNames {
		_, err := fw.ti.Table(table, nftables.TableFamilyINet)
		if err == nil {
			// Table exists, flush it
			if err := fw.ti.DeleteImm(table, nftables.TableFamilyINet); err != nil {
				return fmt.Errorf("failed to flush table: %w", err)
			}
		}
		if err := fw.ti.CreateImm(table, nftables.TableFamilyINet); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}
	filterchains, err := fw.ti.Table(filterTable, nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("failed to load filter table: %w", err)
	}
	natchains, err := fw.ti.Table(natTable, nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("failed to load NAT table: %w", err)
	}
	rawchains, err := fw.ti.Table(rawTable, nftables.TableFamilyINet)
	if err != nil {
		return fmt.Errorf("failed to load raw table: %w", err)
	}
	fw.filterchains = filterchains.Chains()
	fw.natchains = natchains.Chains()
	fw.rawchains = rawchains.Chains()
	return nil
}

func (fw *firewall) initChains() error {
	var defaultFilterPolicy nftableslib.ChainPolicy
	switch fw.opts.DefaultPolicy {
	case PolicyAccept, "":
		defaultFilterPolicy = nftableslib.ChainPolicyAccept
	case PolicyDrop:
		defaultFilterPolicy = nftableslib.ChainPolicyDrop
	default:
		return fmt.Errorf("invalid default policy: %s", fw.opts.DefaultPolicy)
	}
	var err error
	// Create raw chain
	err = fw.rawchains.CreateImm(inetRawPrerouting, &nftableslib.ChainAttributes{
		Type:     nftables.ChainTypeFilter,
		Hook:     nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRaw,
	})
	if err != nil {
		return fmt.Errorf("failed to create raw chain: %w", err)
	}
	// Create prerouting chains
	err = fw.natchains.CreateImm(inetPreroutingChain, &nftableslib.ChainAttributes{
		Type:     nftables.ChainTypeNAT,
		Hook:     nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	})
	if err != nil {
		return fmt.Errorf("failed to create prerouting chain: %w", err)
	}
	// Create postrouting chain
	err = fw.natchains.CreateImm(inetPostRoutingChain, &nftableslib.ChainAttributes{
		Type:     nftables.ChainTypeNAT,
		Hook:     nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})
	if err != nil {
		return fmt.Errorf("failed to create postrouting chain: %w", err)
	}
	// Create the output chain
	err = fw.natchains.CreateImm(inetOutputChain, &nftableslib.ChainAttributes{
		Type:     nftables.ChainTypeNAT,
		Hook:     nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityMangle,
	})
	if err != nil {
		return fmt.Errorf("failed to create output chain: %w", err)
	}
	// Create the input filter chain
	err = fw.filterchains.CreateImm(inetInputChain, &nftableslib.ChainAttributes{
		Type:     nftables.ChainTypeFilter,
		Hook:     nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &defaultFilterPolicy,
	})
	if err != nil {
		return fmt.Errorf("failed to create filter chain: %w", err)
	}
	// Create the forward filter chain
	err = fw.filterchains.CreateImm(inetForwardChain, &nftableslib.ChainAttributes{
		Type:     nftables.ChainTypeFilter,
		Hook:     nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &defaultFilterPolicy,
	})
	if err != nil {
		return fmt.Errorf("failed to create filter chain: %w", err)
	}
	// Load the chain interfaces
	fw.rawprerouting, err = fw.rawchains.Chain(inetRawPrerouting)
	if err != nil {
		return fmt.Errorf("failed to load raw chain: %w", err)
	}
	fw.prerouting, err = fw.natchains.Chain(inetPreroutingChain)
	if err != nil {
		return fmt.Errorf("failed to load prerouting chain: %w", err)
	}
	fw.postrouting, err = fw.natchains.Chain(inetPostRoutingChain)
	if err != nil {
		return fmt.Errorf("failed to load postrouting chain: %w", err)
	}
	fw.output, err = fw.natchains.Chain(inetOutputChain)
	if err != nil {
		return fmt.Errorf("failed to load natprerouting chain: %w", err)
	}
	fw.input, err = fw.filterchains.Chain(inetInputChain)
	if err != nil {
		return fmt.Errorf("failed to load filter chain: %w", err)
	}
	fw.forward, err = fw.filterchains.Chain(inetForwardChain)
	if err != nil {
		return fmt.Errorf("failed to load filter chain: %w", err)
	}
	return nil
}

func (fw *firewall) initInputChain() error {
	accept, err := nftableslib.SetVerdict(nftableslib.NFT_ACCEPT)
	if err != nil {
		return fmt.Errorf("failed to create accept verdict: %w", err)
	}
	drop, err := nftableslib.SetVerdict(nftableslib.NFT_DROP)
	if err != nil {
		return fmt.Errorf("failed to create drop verdict: %w", err)
	}
	var ctInvalid [4]byte
	binary.BigEndian.PutUint32(ctInvalid[:], uint32(nftableslib.CTStateInvalid))
	var ctEstablishedRelated [4]byte
	binary.BigEndian.PutUint32(ctEstablishedRelated[:], uint32(nftableslib.CTStateEstablished|nftableslib.CTStateRelated))

	rules := []struct {
		comment string
		cmd     string
		rule    *nftableslib.Rule
	}{
		{
			comment: "early drop of invalid connections",
			rule: &nftableslib.Rule{
				Conntracks: []*nftableslib.Conntrack{
					{
						Key:   uint32(expr.CtKeySTATE),
						Value: ctInvalid[:],
					},
				},
				Action: drop,
			},
		},
		{
			comment: "allow tracked connections",
			rule: &nftableslib.Rule{
				Conntracks: []*nftableslib.Conntrack{
					{
						Key:   uint32(expr.CtKeySTATE),
						Value: ctEstablishedRelated[:],
					},
				},
				Action: accept,
			},
		},
		{
			comment: "allow from loopback",
			rule: &nftableslib.Rule{
				Meta: &nftableslib.Meta{
					Expr: []nftableslib.MetaExpr{
						{
							Key:   uint32(expr.MetaKeyIIFNAME),
							Value: []byte("lo"),
						},
					},
				},
				Action: accept,
			},
		},
		{
			comment: "allow icmp",
			rule: &nftableslib.Rule{
				Meta: &nftableslib.Meta{
					Expr: []nftableslib.MetaExpr{
						{
							Key:   uint32(expr.MetaKeyL4PROTO),
							Value: []byte{unix.IPPROTO_ICMP},
						},
					},
				},
				Action: accept,
			},
		},
		{
			comment: "allow icmp v6",
			rule: &nftableslib.Rule{
				Meta: &nftableslib.Meta{
					Expr: []nftableslib.MetaExpr{
						{
							Key:   uint32(expr.MetaKeyL4PROTO),
							Value: []byte{unix.IPPROTO_ICMPV6},
						},
					},
				},
				Action: accept,
			},
		},
		{
			comment: "allow ssh",
			rule: &nftableslib.Rule{
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_TCP,
					Dst: &nftableslib.Port{
						List: nftableslib.SetPortList([]int{22}),
					},
				},
				Action: accept,
			},
		},
		{
			comment: "allow wireguard",
			rule: &nftableslib.Rule{
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_UDP,
					Dst: &nftableslib.Port{
						List: nftableslib.SetPortList([]int{int(fw.opts.WireguardPort)}),
					},
				},
				Action: accept,
			},
		},
	}
	if fw.opts.GRPCPort > 0 {
		rules = append(rules, struct {
			comment string
			cmd     string
			rule    *nftableslib.Rule
		}{
			comment: "allow grpc",
			rule: &nftableslib.Rule{
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_TCP,
					Dst: &nftableslib.Port{
						List: nftableslib.SetPortList([]int{int(fw.opts.GRPCPort)}),
					},
				},
				Action: accept,
			},
		})
	}
	if fw.opts.StoragePort > 0 {
		rules = append(rules, struct {
			comment string
			cmd     string
			rule    *nftableslib.Rule
		}{
			comment: "allow raft",
			rule: &nftableslib.Rule{
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_TCP,
					Dst: &nftableslib.Port{
						List: nftableslib.SetPortList([]int{int(fw.opts.StoragePort)}),
					},
				},
				Action: accept,
			},
		})
	}

	for _, rule := range rules {
		rule.rule.UserData = nftableslib.MakeRuleComment(rule.comment)
		_, err = fw.input.Rules().CreateImm(rule.rule)
		if err != nil {
			return fmt.Errorf("failed to add %s rule to input chain: %w", rule.comment, err)
		}
	}

	return nil
}
