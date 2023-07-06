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

// Package firewall contains an interface for interacting with the system firewall.
package firewall

import (
	"context"
	"net/netip"
)

// Firewall is an interface for interacting with the necessary system firewall rules on a router.
type Firewall interface {
	// AddWireguardForwarding should configure the firewall to allow forwarding traffic on the wireguard interface.
	AddWireguardForwarding(ctx context.Context, ifaceName string) error
	// AddMasquerade should configure the firewall to masquerade outbound traffic on the wireguard interface.
	AddMasquerade(ctx context.Context, ifaceName string) error
	// Clear should clear any changes made to the firewall.
	Clear(ctx context.Context) error
	// Close should close any resources used by the firewall. It should also perform a Clear.
	Close(ctx context.Context) error
}

// Policy is a firewall policy.
type Policy string

const (
	// PolicyAccept is the accept firewall policy.
	PolicyAccept Policy = "accept"
	// PolicyDrop is the drop firewall policy.
	PolicyDrop Policy = "drop"
)

// Options are options for configuring a firewall.
type Options struct {
	// DefaultPolicy is the default policy for the firewall.
	DefaultPolicy Policy
	// WireguardPort is the port to allow for wireguard traffic.
	WireguardPort uint16
	// RaftPort is the port to allow for raft traffic.
	RaftPort uint16
	// GRPCPort is the port to allow for grpc traffic.
	GRPCPort uint16
}

// New returns a new firewall manager for the given options.
func New(opts *Options) (Firewall, error) {
	return newFirewall(opts)
}

// DNATOptions are options for configuring a postrouting rule.
type DNATOptions struct {
	// Protocol is the protocol to apply the rule to.
	Protocol string
	// SrcPrefix is the source IP prefix to apply the rule to.
	SrcPrefix netip.Prefix
	// DstPrefix is the destination IP prefix to apply the rule to.
	// If left unset, masquerade will be used. Note that masquerade
	// will only work if the the source knows to route desired traffic
	// towards this router.
	DstPrefix netip.Prefix
	// PortRange is the port range to apply the rule to.
	PortRange *PortRange
}

// PortRange is a range of ports.
type PortRange struct {
	// Start is the start of the port range.
	Start uint16
	// End is the end of the port range.
	End uint16
}
