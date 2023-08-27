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

package netutil

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/webmeshproj/webmesh/pkg/util/crypto"
)

const defaultTestCount = 100

// FuzzGenerateULA is just for checking that we consistently generate valid /48 ULAs.
func FuzzGenerateULA(t *testing.F) {
	for i := 0; i <= defaultTestCount; i++ {
		t.Add(i)
	}
	t.Fuzz(func(t *testing.T, _ int) {
		t.Parallel()
		ula, err := GenerateULA()
		if err != nil {
			t.Fatalf("failed to generate ULA: %s", err)
		}
		if !ula.IsValid() {
			t.Fatalf("generated invalid ULA: %s", ula)
		}
		if ula.Bits() != 48 {
			t.Fatalf("generated ULA with invalid prefix length: %s", ula)
		}
	})
}

// FuzzGenerateULAWithPSK is for checking that given a PSK we consistently generate
// the same /48 ULA.
func FuzzGenerateULAWithPSK(t *testing.F) {
	for i := 0; i <= defaultTestCount; i++ {
		t.Add(crypto.MustGeneratePSK().String())
	}
	t.Fuzz(func(t *testing.T, psk string) {
		t.Parallel()
		lastPrefix := GenerateULAWithPSK([]byte(psk))
		for i := 0; i <= defaultTestCount; i++ {
			prefix := GenerateULAWithPSK([]byte(psk))
			if !prefix.IsValid() {
				t.Fatalf("generated invalid ULA: %s", prefix)
			}
			if prefix.Bits() != 48 {
				t.Fatalf("generated ULA with invalid prefix length: %s", prefix)
			}
			if prefix.String() != lastPrefix.String() {
				t.Errorf("generated different ULA: %s", prefix)
			}
		}
	})
}

// FuzzAssignToPrefix is for checking that given a prefix and a PSK we consistently
// generate the same /96 subnet.
func FuzzAssignToPrefix(f *testing.F) {
	// Generate a ULA for this test iteration
	ula := mustGenerateULA(f)
	for i := 0; i <= 5; i++ {
		f.Add(string(mustGenerateWireguardKey(f)))
	}
	seen := make(map[string]struct{})
	f.Fuzz(func(t *testing.T, key string) {
		prefix, err := AssignToPrefix(ula, []byte(key))
		if err != nil {
			t.Fatalf("failed to assign to prefix: %s", err)
		}
		if !prefix.IsValid() {
			t.Fatalf("generated invalid prefix: %s", prefix)
		}
		if prefix.Bits() != 96 {
			t.Fatalf("generated prefix with invalid prefix length: %s", prefix)
		}
		if _, ok := seen[prefix.String()]; ok {
			t.Errorf("generated duplicate prefix: %s", prefix)
		}
	})
}

func mustGenerateULA(t *testing.F) netip.Prefix {
	t.Helper()
	ula, err := GenerateULA()
	if err != nil {
		t.Fatalf("failed to generate ULA: %s", err)
	}
	return ula
}

func mustGenerateWireguardKey(t *testing.F) []byte {
	t.Helper()
	key, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate WireGuard key: %s", err)
	}
	return key[:]
}
