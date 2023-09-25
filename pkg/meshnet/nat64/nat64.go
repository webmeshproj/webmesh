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

// Package nat64 provides a stateless bi-directional NAT64 implementation. It is
// based on eBPF and XDP and is intended to be used in conjunction with a mesh network.
//
// TODO: The intention of this package is to be a potential option for bridging
// meshes to either the public internet or other meshes. A node could use part of
// its private IPv6 allocation to provide IPv6/IPv4 translation to another mesh. It
// could also use a public IPv6 allocation to provide translation into its current
// mesh. There are other projects capable of providing this functionality, such as
// Jool, but it may be nice to have an option that is more tightly integrated with
// the mesh.
package nat64

import "net/netip"

// Options contains the configuration options for a NAT64 instance.
type Options struct {
	// The interfaces to swap IPv4 and IPv6 addresses on.
	LIface, RIface string
	// The IPv6 prefixes to use for translation.
	LPrefixV6, RPrefixV6 netip.Prefix
	// The IPv4 prefixes to use for translation.
	LPrefixV4, RPrefixV4 netip.Prefix
}
