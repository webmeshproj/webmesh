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

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// NetworkState wraps a NetworkState.
type NetworkState struct{ *v1.NetworkState }

// Proto returns the underlying protobuf.
func (n NetworkState) Proto() *v1.NetworkState {
	return n.NetworkState
}

// DeepCopy returns a deep copy of the network state.
func (n NetworkState) DeepCopy() NetworkState {
	return NetworkState{NetworkState: n.NetworkState.DeepCopy()}
}

// DeepCopyInto copies the node into the given network state.
func (n NetworkState) DeepCopyInto(group *NetworkState) {
	*group = n.DeepCopy()
}

// MarshalProtoJSON marshals the network state to JSON.
func (n NetworkState) MarshalProtoJSON() ([]byte, error) {
	return protojson.Marshal(n.NetworkState)
}

// UnmarshalProtoJSON unmarshals the network state from JSON.
func (n *NetworkState) UnmarshalProtoJSON(data []byte) error {
	var state v1.NetworkState
	if err := protojson.Unmarshal(data, &state); err != nil {
		return err
	}
	n.NetworkState = &state
	return nil
}

// NetworkV4 returns the IPv4 network as a netip.Prefix.
func (n NetworkState) NetworkV4() netip.Prefix {
	var prefix netip.Prefix
	if n.GetNetworkV4() == "" {
		return prefix
	}
	prefix, _ = netip.ParsePrefix(n.GetNetworkV4())
	return prefix
}

// NetworkV4 returns the IPv6 network as a netip.Prefix.
func (n NetworkState) NetworkV6() netip.Prefix {
	var prefix netip.Prefix
	if n.GetNetworkV6() == "" {
		return prefix
	}
	prefix, _ = netip.ParsePrefix(n.GetNetworkV6())
	return prefix
}

// Domain returns the domain.
func (n NetworkState) Domain() string {
	return n.GetDomain()
}
