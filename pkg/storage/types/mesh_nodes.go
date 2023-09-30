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

package types

import (
	"net/netip"
	"slices"
	"sort"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// NodeID is the type of a node ID.
type NodeID string

// String returns the string representation of the node ID.
func (id NodeID) String() string { return string(id) }

// Bytes returns the byte representation of the node ID.
func (id NodeID) Bytes() []byte { return []byte(id) }

// IsEmpty returns true if the node ID is empty.
func (id NodeID) IsEmpty() bool { return id == "" }

// MeshNode wraps a mesh node.
type MeshNode struct {
	*v1.MeshNode `json:",inline"`
}

// MeshNodesEqual compares two mesh nodes for equality.
func MeshNodesEqual(a, b MeshNode) bool {
	sort.Strings(a.WireguardEndpoints)
	sort.Strings(b.WireguardEndpoints)
	return a.Id == b.Id &&
		a.PublicKey == b.PublicKey &&
		a.PrimaryEndpoint == b.PrimaryEndpoint &&
		a.ZoneAwarenessId == b.ZoneAwarenessId &&
		a.PrivateIpv4 == b.PrivateIpv4 &&
		a.PrivateIpv6 == b.PrivateIpv6 &&
		slices.Equal(a.WireguardEndpoints, b.WireguardEndpoints) &&
		FeaturePortsEqual(a.Features, b.Features)
}

// DeepCopy returns a deep copy of the node.
func (n MeshNode) DeepCopy() MeshNode {
	return MeshNode{MeshNode: n.MeshNode.DeepCopy()}
}

// DeepCopyInto copies the node into the given node.
func (n MeshNode) DeepCopyInto(node *MeshNode) {
	*node = n.DeepCopy()
}

// DeepEqual returns true if the node is deeply equal to the given node.
func (n MeshNode) DeepEqual(node MeshNode) bool {
	return MeshNodesEqual(n, node)
}

// NodeID returns the node's ID.
func (n MeshNode) NodeID() NodeID {
	return NodeID(n.GetId())
}

// MarshalJSON marshals the node to JSON.
func (n MeshNode) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(n.MeshNode)
}

// UnmarshalJSON unmarshals the node from JSON.
func (n *MeshNode) UnmarshalJSON(data []byte) error {
	var node v1.MeshNode
	if err := protojson.Unmarshal(data, &node); err != nil {
		return err
	}
	n.MeshNode = &node
	return nil
}

// HasFeature returns true if the node has the given feature.
func (n MeshNode) HasFeature(feature v1.Feature) bool {
	for _, f := range n.Features {
		if f.Feature == feature {
			return true
		}
	}
	return false
}

// PortFor returns the port for the given feature, or 0
// if the feature is not available on this node.
func (n MeshNode) PortFor(feature v1.Feature) uint16 {
	for _, f := range n.Features {
		if f.Feature == feature {
			return uint16(f.Port)
		}
	}
	return 0
}

// RPCPort returns the node's RPC port.
func (n MeshNode) RPCPort() uint16 {
	return n.PortFor(v1.Feature_NODES)
}

// DNSPort returns the node's DNS port.
func (n MeshNode) DNSPort() uint16 {
	return n.PortFor(v1.Feature_MESH_DNS)
}

// TURNPort returns the node's TURN port.
func (n MeshNode) TURNPort() uint16 {
	return n.PortFor(v1.Feature_TURN_SERVER)
}

// StoragePort returns the node's Storage port.
func (n MeshNode) StoragePort() uint16 {
	return n.PortFor(v1.Feature_STORAGE_PROVIDER)
}

// PrivateAddrV4 returns the node's private IPv4 address.
// Be sure to check if the returned Addr IsValid.
func (n MeshNode) PrivateAddrV4() netip.Prefix {
	if n.GetPrivateIpv4() == "" {
		return netip.Prefix{}
	}
	addr, err := netip.ParsePrefix(n.GetPrivateIpv4())
	if err != nil {
		return netip.Prefix{}
	}
	return addr
}

// PrivateAddrV6 returns the node's private IPv6 address.
// Be sure to check if the returned Addr IsValid.
func (n MeshNode) PrivateAddrV6() netip.Prefix {
	if n.GetPrivateIpv6() == "" {
		return netip.Prefix{}
	}
	addr, err := netip.ParsePrefix(n.GetPrivateIpv6())
	if err != nil {
		return netip.Prefix{}
	}
	return addr
}

// PublicRPCAddr returns the public address for the node's RPC server.
// Be sure to check if the returned AddrPort IsValid.
func (n MeshNode) PublicRPCAddr() netip.AddrPort {
	rpcport := n.RPCPort()
	if rpcport == 0 {
		return netip.AddrPort{}
	}
	var addrport netip.AddrPort
	if n.PrimaryEndpoint != "" {
		addr, err := netip.ParseAddr(n.PrimaryEndpoint)
		if err == nil {
			addrport = netip.AddrPortFrom(addr, rpcport)
		}
	}
	return addrport
}

// PrivateRPCAddrV4 returns the private IPv4 address for the node's RPC server.
// Be sure to check if the returned AddrPort IsValid.
func (n MeshNode) PrivateRPCAddrV4() netip.AddrPort {
	addr := n.PrivateAddrV4()
	if !addr.IsValid() {
		return netip.AddrPort{}
	}
	rpcport := n.RPCPort()
	if rpcport == 0 {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Addr(), rpcport)
}

// PrivateRPCAddrV6 returns the private IPv6 address for the node's RPC server.
// Be sure to check if the returned AddrPort IsValid.
func (n MeshNode) PrivateRPCAddrV6() netip.AddrPort {
	addr := n.PrivateAddrV6()
	if !addr.IsValid() {
		return netip.AddrPort{}
	}
	rpcport := n.RPCPort()
	if rpcport == 0 {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Addr(), rpcport)
}

// PrivateStorageAddrV4 returns the private IPv4 address for the node's raft listener.
// Be sure to check if the returned AddrPort IsValid.
func (n MeshNode) PrivateStorageAddrV4() netip.AddrPort {
	rpcport := n.StoragePort()
	if rpcport == 0 {
		return netip.AddrPort{}
	}
	addr := n.PrivateAddrV4()
	if !addr.IsValid() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Addr(), rpcport)
}

// PrivateStorageAddrV6 returns the private IPv6 address for the node's raft listener.
// Be sure to check if the returned AddrPort IsValid.
func (n MeshNode) PrivateStorageAddrV6() netip.AddrPort {
	rpcport := n.StoragePort()
	if rpcport == 0 {
		return netip.AddrPort{}
	}
	addr := n.PrivateAddrV6()
	if !addr.IsValid() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Addr(), rpcport)
}

// PublicDNSAddr returns the public address for the node's DNS server.
// Be sure to check if the returned AddrPort IsValid.
func (n MeshNode) PublicDNSAddr() netip.AddrPort {
	if n.PrimaryEndpoint == "" {
		return netip.AddrPort{}
	}
	dnsport := n.DNSPort()
	if dnsport == 0 {
		return netip.AddrPort{}
	}
	var err error
	var addr netip.Addr
	var addrport netip.AddrPort
	addr, err = netip.ParseAddr(n.PrimaryEndpoint)
	if err == nil {
		addrport = netip.AddrPortFrom(addr, dnsport)
	}
	return addrport
}

// PrivateDNSAddrV4 returns the private IPv4 address for the node's DNS server.
// Be sure to check if the returned AddrPort IsValid.
func (n MeshNode) PrivateDNSAddrV4() netip.AddrPort {
	addr := n.PrivateAddrV4()
	if !addr.IsValid() {
		return netip.AddrPort{}
	}
	dnsport := n.DNSPort()
	if dnsport == 0 {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Addr(), dnsport)
}

// PrivateDNSAddrV6 returns the private IPv6 address for the node's DNS server.
// Be sure to check if the returned AddrPort IsValid.
func (n MeshNode) PrivateDNSAddrV6() netip.AddrPort {
	addr := n.PrivateAddrV6()
	if !addr.IsValid() {
		return netip.AddrPort{}
	}
	dnsport := n.DNSPort()
	if dnsport == 0 {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Addr(), dnsport)
}

// PrivateTURNAddrV4 returns the private IPv4 address for the node's TURN server.
// Be sure to check if the returned AddrPort IsValid.
func (n MeshNode) PrivateTURNAddrV4() netip.AddrPort {
	addr := n.PrivateAddrV4()
	if !addr.IsValid() {
		return netip.AddrPort{}
	}
	turnport := n.TURNPort()
	if turnport == 0 {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Addr(), turnport)
}

// PrivateTURNAddrV6 returns the private IPv6 address for the node's TURN server.
// Be sure to check if the returned AddrPort IsValid.
func (n MeshNode) PrivateTURNAddrV6() netip.AddrPort {
	addr := n.PrivateAddrV6()
	if !addr.IsValid() {
		return netip.AddrPort{}
	}
	turnport := n.TURNPort()
	if turnport == 0 {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Addr(), turnport)
}
