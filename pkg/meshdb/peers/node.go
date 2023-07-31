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

// Package peers contains an interface for managing nodes in the mesh.
package peers

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Node represents a node. Not all fields are populated in all contexts.
// A fully populated node is returned by Get and List.
type Node struct {
	// ID is the node's ID.
	ID string `json:"id"`
	// PublicKey is the node's public key.
	PublicKey wgtypes.Key `json:"publicKey"`
	// PrimaryEndpoint is the primary public endpoint of the node.
	PrimaryEndpoint string `json:"primaryEndpoint"`
	// WireGuardEndpoints are the available wireguard endpoints of the node.
	WireGuardEndpoints []string `json:"wireGuardEndpoints"`
	// ZoneAwarenessID is the node's zone awareness ID.
	ZoneAwarenessID string `json:"zoneAwarenessId"`
	// PrivateIPv4 is the node's private IPv4 address.
	PrivateIPv4 netip.Prefix `json:"privateIpv4"`
	// PrivateIPv6 is the node's IPv6 network.
	PrivateIPv6 netip.Prefix `json:"privateIpv6"`
	// GRPCPort is the node's GRPC port.
	GRPCPort int `json:"grpcPort"`
	// RaftPort is the node's Raft port.
	RaftPort int `json:"raftPort"`
	// DNSPort is the node's DNS port.
	DNSPort int `json:"dnsPort"`
	// Features are the node's features.
	Features []v1.Feature `json:"features"`
	// UpdatedAt is the time the node was last updated.
	UpdatedAt time.Time `json:"updatedAt"`
}

// HasFeature returns true if the node has the given feature.
func (n Node) HasFeature(feature v1.Feature) bool {
	for _, f := range n.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// PublicRPCAddr returns the public address for the node's RPC server.
// Be sure to check if the returned AddrPort IsValid.
func (n Node) PublicRPCAddr() netip.AddrPort {
	var addrport netip.AddrPort
	if n.PrimaryEndpoint != "" {
		addr, err := netip.ParseAddr(n.PrimaryEndpoint)
		if err == nil {
			addrport = netip.AddrPortFrom(addr, uint16(n.GRPCPort))
		}
	}
	return addrport
}

// PrivateRPCAddrV4 returns the private IPv4 address for the node's RPC server.
// Be sure to check if the returned AddrPort IsValid.
func (n Node) PrivateRPCAddrV4() netip.AddrPort {
	var addrport netip.AddrPort
	if n.PrivateIPv4.IsValid() {
		addrport = netip.AddrPortFrom(n.PrivateIPv4.Addr(), uint16(n.GRPCPort))
	}
	return addrport
}

// PrivateRPCAddrV6 returns the private IPv6 address for the node's RPC server.
// Be sure to check if the returned AddrPort IsValid.
func (n Node) PrivateRPCAddrV6() netip.AddrPort {
	var addrport netip.AddrPort
	if n.PrivateIPv6.IsValid() {
		addrport = netip.AddrPortFrom(n.PrivateIPv6.Addr(), uint16(n.GRPCPort))
	}
	return addrport
}

// PublicDNSAddr returns the public address for the node's DNS server.
// Be sure to check if the returned AddrPort IsValid.
func (n Node) PublicDNSAddr() netip.AddrPort {
	var addrport netip.AddrPort
	if n.DNSPort == 0 {
		return addrport
	}
	if n.PrimaryEndpoint != "" {
		addr, err := netip.ParseAddr(n.PrimaryEndpoint)
		if err == nil {
			addrport = netip.AddrPortFrom(addr, uint16(n.DNSPort))
		}
	}
	return addrport
}

// PrivateDNSAddrV4 returns the private IPv4 address for the node's DNS server.
// Be sure to check if the returned AddrPort IsValid.
func (n Node) PrivateDNSAddrV4() netip.AddrPort {
	var addrport netip.AddrPort
	if n.DNSPort == 0 {
		return addrport
	}
	if n.PrivateIPv4.IsValid() {
		addrport = netip.AddrPortFrom(n.PrivateIPv4.Addr(), uint16(n.DNSPort))
	}
	return addrport
}

// PrivateDNSAddrV6 returns the private IPv6 address for the node's DNS server.
// Be sure to check if the returned AddrPort IsValid.
func (n Node) PrivateDNSAddrV6() netip.AddrPort {
	var addrport netip.AddrPort
	if n.DNSPort == 0 {
		return addrport
	}
	if n.PrivateIPv6.IsValid() {
		addrport = netip.AddrPortFrom(n.PrivateIPv6.Addr(), uint16(n.DNSPort))
	}
	return addrport
}

// MarshalJSON marshals a Node to JSON.
func (n Node) MarshalJSON() ([]byte, error) {
	type Alias Node
	return json.Marshal(&struct {
		PublicKey   string `json:"publicKey"`
		PrivateIPv4 string `json:"privateIpv4"`
		PrivateIPv6 string `json:"privateIpv6"`
		Alias
	}{
		PublicKey: n.PublicKey.String(),
		PrivateIPv4: func() string {
			if n.PrivateIPv4.IsValid() {
				return n.PrivateIPv4.String()
			}
			return ""
		}(),
		PrivateIPv6: func() string {
			if n.PrivateIPv6.IsValid() {
				return n.PrivateIPv6.String()
			}
			return ""
		}(),
		Alias: (Alias)(n),
	})
}

// UnmarshalJSON unmarshals a Node from JSON.
func (n *Node) UnmarshalJSON(b []byte) error {
	type Alias Node
	aux := &struct {
		PublicKey   string `json:"publicKey"`
		PrivateIPv4 string `json:"privateIpv4"`
		PrivateIPv6 string `json:"privateIpv6"`
		*Alias
	}{
		Alias: (*Alias)(n),
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if aux.PublicKey != "" {
		key, err := wgtypes.ParseKey(aux.PublicKey)
		if err != nil {
			return fmt.Errorf("parse node public key: %w", err)
		}
		n.PublicKey = key
	}
	if aux.PrivateIPv4 != "" {
		network, err := netip.ParsePrefix(aux.PrivateIPv4)
		if err != nil {
			return fmt.Errorf("parse node private IPv4: %w", err)
		}
		n.PrivateIPv4 = network
	}
	if aux.PrivateIPv6 != "" {
		network, err := netip.ParsePrefix(aux.PrivateIPv6)
		if err != nil {
			return fmt.Errorf("parse node private IPv6: %w", err)
		}
		n.PrivateIPv6 = network
	}
	return nil
}

// Proto converts a Node to the protobuf representation.
func (n *Node) Proto(status v1.ClusterStatus) *v1.MeshNode {
	return &v1.MeshNode{
		Id:                 n.ID,
		PrimaryEndpoint:    n.PrimaryEndpoint,
		WireguardEndpoints: n.WireGuardEndpoints,
		ZoneAwarenessId:    n.ZoneAwarenessID,
		RaftPort:           int32(n.RaftPort),
		GrpcPort:           int32(n.GRPCPort),
		MeshdnsPort:        int32(n.DNSPort),
		PublicKey: func() string {
			if len(n.PublicKey) > 0 {
				return n.PublicKey.String()
			}
			return ""
		}(),
		PrivateIpv4: func() string {
			if n.PrivateIPv4.IsValid() {
				return n.PrivateIPv4.String()
			}
			return ""
		}(),
		PrivateIpv6: func() string {
			if n.PrivateIPv6.IsValid() {
				return n.PrivateIPv6.String()
			}
			return ""
		}(),
		Features:  n.Features,
		UpdatedAt: timestamppb.New(n.UpdatedAt),
		// TODO: Get rid of this field.
		CreatedAt:     timestamppb.New(n.UpdatedAt),
		ClusterStatus: status,
	}
}
