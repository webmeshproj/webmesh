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

package wireguard

import (
	"net/netip"
)

// Peer contains configurations for a wireguard peer. When removing,
// only the PublicKey is required.
type Peer struct {
	// ID is the ID of the peer.
	ID string `json:"id"`
	// PublicKey is the public key of the peer.
	PublicKey string `json:"publicKey"`
	// Endpoint is the endpoint of this peer, if applicable.
	Endpoint string `json:"endpoint"`
	// AdditionalEndpoints are additional endpoints that can be tried
	// for this peer.
	AdditionalEndpoints []string `json:"additionalEndpoints"`
	// PrivateIPv4 is the private IPv4 address of the peer.
	PrivateIPv4 netip.Prefix `json:"privateIPv4"`
	// PrivateIPv6 is the private IPv6 address of the peer.
	PrivateIPv6 netip.Prefix `json:"privateIPv6"`
}

// IsPubliclyRoutable returns true if the given peer is publicly routable.
// We trust that the user configured an endpoint on top of any additional
// ones.
func (p *Peer) IsPubliclyRoutable() bool {
	return p.Endpoint != ""
}
