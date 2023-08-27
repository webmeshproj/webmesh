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

package endpoints

import (
	"net/netip"
)

// DetectOpts contains options for endpoint detection.
type DetectOpts struct {
	// DetectIPv6 enables IPv6 detection.
	DetectIPv6 bool
	// DetectPrivate enables private address detection.
	DetectPrivate bool
	// AllowRemoteDetection enables remote address detection.
	AllowRemoteDetection bool
	// SkipInterfaces contains a list of interfaces to skip.
	SkipInterfaces []string
}

type PrefixList []netip.Prefix

func (a PrefixList) Contains(addr netip.Addr) bool {
	for _, prefix := range a {
		if prefix.Addr().Compare(addr) == 0 || prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (a PrefixList) Strings() []string {
	var out []string
	for _, addr := range a {
		out = append(out, addr.String())
	}
	return out
}

func (a PrefixList) AddrStrings() []string {
	var out []string
	for _, addr := range a {
		out = append(out, addr.Addr().String())
	}
	return out
}

func (a PrefixList) Len() int      { return len(a) }
func (a PrefixList) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

// Sort by IPv4 addresses first, then IPv6 addresses.
func (a PrefixList) Less(i, j int) bool {
	iis4 := a[i].Addr().Is4()
	jis4 := a[j].Addr().Is4()
	if iis4 && !jis4 {
		return true
	}
	if !iis4 && jis4 {
		return false
	}
	return a[i].Addr().Less(a[j].Addr())
}
