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

package testutil

import (
	"context"
	"net/netip"
	"testing"

	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
)

// NewMeshStateFunc is a function that creates a new MeshState implementation.
type NewMeshStateFunc func(t *testing.T) storage.MeshState

// TestMeshStateStorageConformance tests that a MeshState implementation conforms to the interface.
func TestMeshStateStorageConformance(t *testing.T, builder NewMeshStateFunc) {
	ctx := context.Background()

	t.Run("MeshStateConformance", func(t *testing.T) {

		t.Run("GetSetIPv6Prefix", func(t *testing.T) {
			st := builder(t)
			// There should be no prefix set.
			_, err := st.GetIPv6Prefix(ctx)
			if err == nil {
				t.Fatal("expected error, got nil")
			} else if !errors.IsKeyNotFound(err) {
				t.Fatalf("expected key not found, got %v", err)
			}
			// We should be able to set a prefix.
			prefix := netip.MustParsePrefix("2001:db8::/64")
			err = st.SetIPv6Prefix(ctx, prefix)
			if err != nil {
				t.Fatalf("failed to set prefix: %v", err)
			}
			// We should be able to get the prefix.
			got, err := st.GetIPv6Prefix(ctx)
			if err != nil {
				t.Fatalf("failed to get prefix: %v", err)
			}
			if prefix.Bits() != got.Bits() {
				t.Fatalf("expected prefix %v, got %v", prefix, got)
			}
			if prefix.Addr().Compare(got.Addr()) != 0 {
				t.Fatalf("expected prefix %v, got %v", prefix, got)
			}
		})

		t.Run("GetSetIPv4Prefix", func(t *testing.T) {
			st := builder(t)
			// There should be no prefix set.
			_, err := st.GetIPv4Prefix(ctx)
			if err == nil {
				t.Fatal("expected error, got nil")
			} else if !errors.IsKeyNotFound(err) {
				t.Fatalf("expected key not found, got %v", err)
			}
			// We should be able to set a prefix.
			prefix := netip.MustParsePrefix("172.16.0.0/16")
			err = st.SetIPv4Prefix(ctx, prefix)
			if err != nil {
				t.Fatalf("failed to set prefix: %v", err)
			}
			// We should be able to get the prefix.
			got, err := st.GetIPv4Prefix(ctx)
			if err != nil {
				t.Fatalf("failed to get prefix: %v", err)
			}
			if prefix.Bits() != got.Bits() {
				t.Fatalf("expected prefix %v, got %v", prefix, got)
			}
			if prefix.Addr().Compare(got.Addr()) != 0 {
				t.Fatalf("expected prefix %v, got %v", prefix, got)
			}
		})

		t.Run("GetSetMeshDomain", func(t *testing.T) {
			st := builder(t)
			// There should be no domain set.
			_, err := st.GetMeshDomain(ctx)
			if err == nil {
				t.Fatal("expected error, got nil")
			} else if !errors.IsKeyNotFound(err) {
				t.Fatalf("expected key not found, got %v", err)
			}
			// We should be able to set a domain.
			domain := "example.com"
			err = st.SetMeshDomain(ctx, domain)
			if err != nil {
				t.Fatalf("failed to set domain: %v", err)
			}
			// We should be able to get the domain.
			got, err := st.GetMeshDomain(ctx)
			if err != nil {
				t.Fatalf("failed to get domain: %v", err)
			}
			if domain != got {
				t.Fatalf("expected domain %s, got %s", domain, got)
			}
		})
	})
}
