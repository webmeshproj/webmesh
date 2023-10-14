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

import "net/netip"

// Prefix is wraps a netip.Prefix with a custom JSON marshaller.
type Prefix struct{ netip.Prefix }

// ParsePrefix parses a string into a Prefix.
func ParsePrefix(s string) (Prefix, error) {
	p, err := netip.ParsePrefix(s)
	return Prefix{p}, err
}

// MustParsePrefix parses a string into a Prefix and panics on error.
func MustParsePrefix(s string) Prefix {
	p, err := ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

// MarshalJSON marshals a Prefix as a string.
func (p Prefix) MarshalJSON() ([]byte, error) {
	if !p.IsValid() {
		return []byte(`""`), nil
	}
	return []byte("\"" + p.String() + "\""), nil
}

// UnmarshalJSON unmarshals a Prefix from a string.
func (p *Prefix) UnmarshalJSON(b []byte) error {
	if string(b) == "null" || string(b) == `""` {
		return nil
	}
	var err error
	p.Prefix, err = netip.ParsePrefix(string(b))
	if err != nil {
		return err
	}
	return nil
}
