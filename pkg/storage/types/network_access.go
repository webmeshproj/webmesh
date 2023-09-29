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
)

// NetworkAction wraps a NetworkAction.
type NetworkAction struct {
	*v1.NetworkAction
}

// Proto returns the protobuf representation of the action.
func (a *NetworkAction) Proto() *v1.NetworkAction {
	return a.NetworkAction
}

// SourcePrefix returns the source prefix for the action if it is valid.
func (a *NetworkAction) SourcePrefix() netip.Prefix {
	if a.GetSrcCidr() == "" {
		return netip.Prefix{}
	}
	if a.GetSrcCidr() == "*" {
		return netip.MustParsePrefix("0.0.0.0/0")
	}
	out, _ := netip.ParsePrefix(a.GetSrcCidr())
	return out
}

// DestinationPrefix returns the destination prefix for the action if it is valid.
func (a *NetworkAction) DestinationPrefix() netip.Prefix {
	if a.GetDstCidr() == "" {
		return netip.Prefix{}
	}
	if a.GetDstCidr() == "*" {
		return netip.MustParsePrefix("0.0.0.0/0")
	}
	out, _ := netip.ParsePrefix(a.GetDstCidr())
	return out
}
