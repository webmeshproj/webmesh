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
	"sort"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slices"
)

// SortedWireGuardPeers implements a sort.Interface for []*v1.WireGuardPeer.
type SortedWireGuardPeers []*v1.WireGuardPeer

func (s SortedWireGuardPeers) Len() int {
	return len(s)
}

func (s SortedWireGuardPeers) Less(i, j int) bool {
	return s[i].GetNode().GetId() < s[j].GetNode().GetId()
}

func (s SortedWireGuardPeers) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// WireGuardPeersEqual recurses the WireGuard peers and compares them for equality.
// Both lists are sorted by ID first.
func WireGuardPeersEqual(a, b []*v1.WireGuardPeer) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Sort(SortedWireGuardPeers(a))
	sort.Sort(SortedWireGuardPeers(b))
	for i, peer := range a {
		if !WireGuardPeerEqual(peer, b[i]) {
			return false
		}
	}
	return true
}

// WireGuardPeerEqual compares two WireGuard peers for equality.
func WireGuardPeerEqual(a, b *v1.WireGuardPeer) bool {
	if a == nil && b != nil {
		return false
	}
	if a != nil && b == nil {
		return false
	}
	if a == nil && b == nil {
		return true
	}
	sort.Strings(a.AllowedIPs)
	sort.Strings(b.AllowedIPs)
	sort.Strings(a.AllowedRoutes)
	sort.Strings(b.AllowedRoutes)
	return a.Proto == b.Proto &&
		MeshNodesEqual(MeshNode{a.Node}, MeshNode{b.Node}) &&
		slices.Equal(a.AllowedIPs, b.AllowedIPs) &&
		slices.Equal(a.AllowedRoutes, b.AllowedRoutes)

}

// FeaturePortsEqual compares two feature ports for equality.
func FeaturePortsEqual(a, b []*v1.FeaturePort) bool {
	if len(a) != len(b) {
		return false
	}
	for i, port := range a {
		if !FeaturePortEqual(port, b[i]) {
			return false
		}
	}
	return true
}

// FeaturePortEqual compares two feature ports for equality.
func FeaturePortEqual(a, b *v1.FeaturePort) bool {
	if a == nil && b != nil {
		return false
	}
	if a != nil && b == nil {
		return false
	}
	if a == nil && b == nil {
		return true
	}
	return a.Feature == b.Feature &&
		a.Port == b.Port
}
