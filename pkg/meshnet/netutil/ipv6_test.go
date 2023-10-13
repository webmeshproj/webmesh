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
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/webmeshproj/webmesh/pkg/crypto"
)

func defaultTestCount(t *testing.F) int {
	t.Helper()
	const defaultTestCount = 10
	// Let this be overriden by an environment variable
	if count := os.Getenv("NETUTIL_FUZZ_SEED_COUNT"); count != "" {
		if c, err := strconv.Atoi(count); err == nil {
			return c
		}
	}
	return defaultTestCount
}

// FuzzGenerateULA is just for checking that we consistently generate valid /32 ULAs.
func FuzzGenerateULA(t *testing.F) {
	for i := 0; i <= defaultTestCount(t); i++ {
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
		if ula.Bits() != DefaultULABits {
			t.Fatalf("generated ULA with invalid prefix length: %s", ula)
		}
	})
}

// FuzzGenerateULAWithSeed is for checking that given a seed we consistently generate
// the same /32 ULA.
func FuzzGenerateULAWithSeed(t *testing.F) {
	tc := defaultTestCount(t)
	for i := 0; i <= tc; i++ {
		t.Add(crypto.MustGeneratePSK().String())
	}
	t.Fuzz(func(t *testing.T, psk string) {
		t.Parallel()
		lastPrefix := GenerateULAWithSeed([]byte(psk))
		for i := 0; i <= tc; i++ {
			prefix := GenerateULAWithSeed([]byte(psk))
			if !prefix.IsValid() {
				t.Fatalf("generated invalid ULA: %s", prefix)
			}
			if prefix.Bits() != DefaultULABits {
				t.Fatalf("generated ULA with invalid prefix length: %s", prefix)
			}
			if prefix.String() != lastPrefix.String() {
				t.Errorf("generated different ULA: %s", prefix)
			}
		}
	})
}

// FuzzAssignToPrefix is for checking that given a prefix and a PSK we consistently
// generate the same /112 subnet.
func FuzzAssignToPrefix(f *testing.F) {
	// Generate a ULA for this test iteration
	ula := mustGenerateULA(f)
	tc := defaultTestCount(f)
	// Seed dummy data we aren't actually going to use
	for i := 0; i <= tc; i++ {
		f.Add(string(mustGenerateSeedKey(f)))
	}
	var seen sync.Map
	var seenKeys sync.Map
	var count atomic.Uint64
	f.Fuzz(func(t *testing.T, key string) {
		// Make sure we don't rerun the test with the same key
		// Make sure we also consumed the fuzz data
		c := io.NopCloser(strings.NewReader(key))
		defer c.Close()
		pubkey := mustGenerateKey(t)
		if _, ok := seenKeys.Load(key); ok {
			t.SkipNow()
			t.Logf("skipping duplicate key %q", key)
			return
		}
		seenKeys.Store(key, struct{}{})
		// Make sure we get a valid prefix
		prefix := AssignToPrefix(ula, pubkey)
		if !prefix.IsValid() {
			t.Fatalf("generated invalid prefix: %s", prefix)
		}
		if prefix.Bits() != DefaultNodeBits {
			t.Fatalf("generated prefix with invalid prefix length: %s", prefix)
		}
		if !ula.Contains(prefix.Addr()) {
			t.Fatalf("generated prefix %q not contained in ULA %q", prefix.String(), ula.String())
		}
		if _, ok := seen.Load(prefix); ok {
			t.Fatalf("generated duplicate prefix %q after %d runs", prefix.String(), count.Load())
		}
		// Make sure no previously generated prefix contains this one
		seen.Range(func(key, value any) bool {
			seenPrefix := key.(netip.Prefix)
			if seenPrefix.Contains(prefix.Addr()) {
				t.Fatalf("generated prefix %q contains %q", prefix.String(), prefix.String())
			}
			return true
		})
		// Make sure we generate the same prefix for the same key
		toCheck := AssignToPrefix(ula, pubkey)
		if toCheck.String() != prefix.String() {
			t.Fatalf("generated different prefix for same key: %s", prefix)
		}
		// Make sure we don't generate the same prefix for different keys
		seen.Store(prefix, struct{}{})
		count.Add(1)
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

func mustGenerateKey(t *testing.T) crypto.PublicKey {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate WireGuard key: %s", err)
	}
	return key.PublicKey()
}

func mustGenerateSeedKey(t *testing.F) []byte {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate WireGuard key: %s", err)
	}
	pubkey := key.PublicKey().Bytes()
	return pubkey[:]
}
