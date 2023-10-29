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
	"time"

	v1 "github.com/webmeshproj/api/go/v1"

	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// NewMeshStateFunc is a function that creates a new MeshState implementation.
type NewMeshStateFunc func(t *testing.T) storage.MeshState

// TestMeshStateStorageConformance tests that a MeshState implementation conforms to the interface.
func TestMeshStateStorageConformance(t *testing.T, builder NewMeshStateFunc) {
	ctx := context.Background()
	t.Run("MeshStateConformance", func(t *testing.T) {
		st := builder(t)
		t.Run("GetSetMeshState", func(t *testing.T) {
			// There should be no state set.
			_, err := st.GetMeshState(ctx)
			if err == nil {
				t.Fatal("expected error, got nil")
			} else if !errors.IsKeyNotFound(err) {
				t.Fatalf("expected key not found, got %v", err)
			}
			// We should be able to set the state
			err = st.SetMeshState(ctx, types.NetworkState{
				NetworkState: &v1.NetworkState{
					NetworkV4: "172.16.0.0/12",
					NetworkV6: "2001:db8::/64",
					Domain:    "example.com",
				},
			})
			if err != nil {
				t.Fatalf("set network state: %v", err)
			}
			// We should eventually get the same mesh domain back.
			var got string
			ok := Eventually[string](func() string {
				state, err := st.GetMeshState(ctx)
				if err != nil {
					t.Logf("failed to get mesh state: %v", err)
					return ""
				}
				got = state.Domain()
				return got
			}).ShouldEqual(time.Second*15, time.Second, "example.com")
			if !ok {
				t.Fatalf("expected domain %q, got %q", "example.com", got)
			}
			// We should eventually get the same ipv4 back.
			var gotcidr netip.Prefix
			expected := netip.MustParsePrefix("172.16.0.0/12")
			ok = Eventually[netip.Prefix](func() netip.Prefix {
				state, err := st.GetMeshState(ctx)
				if err != nil {
					t.Logf("failed to get mesh state: %v", err)
					return netip.Prefix{}
				}
				gotcidr = state.NetworkV4()
				return gotcidr
			}).ShouldEqual(time.Second*15, time.Second, expected)
			if !ok {
				t.Fatalf("expected network %s, got %s", expected, gotcidr)
			}
			// We should eventually get the same ipv6 back.
			gotcidr = netip.Prefix{}
			expected = netip.MustParsePrefix("2001:db8::/64")
			ok = Eventually[netip.Prefix](func() netip.Prefix {
				state, err := st.GetMeshState(ctx)
				if err != nil {
					t.Logf("failed to get mesh state: %v", err)
					return netip.Prefix{}
				}
				gotcidr = state.NetworkV6()
				return gotcidr
			}).ShouldEqual(time.Second*15, time.Second, expected)
			if !ok {
				t.Fatalf("expected network %s, got %s", expected, gotcidr)
			}
		})
	})
}
