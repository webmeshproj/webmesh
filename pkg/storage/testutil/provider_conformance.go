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
	"os"
	"testing"
	"time"

	"github.com/webmeshproj/webmesh/pkg/storage"
)

// TestStorageProviderConformance tests that the storage provider conforms to the
// storage provider interface.
func TestStorageProviderConformance(ctx context.Context, t *testing.T, newProvider NewProviderFunc) {
	t.Run("TestSingleNodeStorageConformance", func(t *testing.T) {
		provider := newProvider(ctx, t)
		defer provider.Close()
		MustBootstrap(ctx, t, provider)
		TestMeshStorageConformance(ctx, t, provider.MeshStorage())
	})

	t.Run("TestThreeNodeStorageConformance", func(t *testing.T) {
		// We define a single test function that we run with different
		// add functions.
		runTest := func(t *testing.T, addFunc func(ctx context.Context, t *testing.T, leader, voter storage.Provider)) {
			providers := map[string]storage.Provider{
				"provider1": newProvider(ctx, t),
				"provider2": newProvider(ctx, t),
				"provider3": newProvider(ctx, t),
			}
			for _, provider := range providers {
				defer provider.Close()
			}
			MustBootstrap(ctx, t, providers["provider1"])
			// Provider 1 must be the leader
			ok := Eventually[bool](func() bool {
				return providers["provider1"].Consensus().IsLeader()
			}).ShouldEqual(time.Second*10, time.Second, true)
			if !ok {
				t.Fatal("Provider 1 is not the leader")
			}
			// Add the others to thr group.
			for _, provider := range []storage.Provider{providers["provider2"], providers["provider3"]} {
				addFunc(ctx, t, providers["provider1"], provider)
			}
			// Each provider should eventually contain three peers.
			for name, provider := range providers {
				p := provider
				ok := Eventually[int](func() int {
					return len(p.Status().GetPeers())
				}).ShouldEqual(time.Second*10, time.Second, 3)
				if !ok {
					t.Fatalf("Provider %s does not have three peers", name)
				}
			}
			// We should be able to write keys to a leader and have them propagate to the followers.
			var leader storage.Provider
			for _, provider := range providers {
				if provider.Consensus().IsLeader() {
					leader = provider
					break
				}
			}
			if leader == nil {
				t.Fatal("No leader found")
			}
			kv := map[string]string{
				"Test/key1": "value1",
				"Test/key2": "value2",
				"Test/key3": "value3",
			}
			for k, v := range kv {
				err := leader.MeshStorage().PutValue(ctx, k, v, 0)
				if err != nil {
					t.Fatalf("Failed to put key %s: %v", k, err)
				}
			}
			// We should eventually have all three keys on all three providers.
			for name, provider := range providers {
				p := provider
				ok := Eventually[int](func() int {
					items, err := p.MeshStorage().List(ctx, "Test/")
					if err != nil {
						t.Log("Error fetching keys", err)
						return 0
					}
					return len(items)
				}).ShouldEqual(time.Second*30, time.Second, 3)
				if !ok {
					t.Fatalf("Provider %s does not have three keys", name)
				}
				// Each key should have the correct value
				for k, v := range kv {
					val, err := p.MeshStorage().GetValue(ctx, k)
					if err != nil {
						t.Fatalf("Failed to get key %s: %v", k, err)
					}
					if val != v {
						t.Fatalf("Expected key %s to have value %s, got %s", k, v, val)
					}
				}
			}
			// Delete the keys and it should propagate
			for k := range kv {
				err := leader.MeshStorage().Delete(ctx, k)
				if err != nil {
					t.Fatalf("Failed to delete key %s: %v", k, err)
				}
			}
			// We should eventually have no keys on all three providers.
			for name, provider := range providers {
				p := provider
				ok := Eventually[int](func() int {
					items, err := p.MeshStorage().List(ctx, "Test/")
					if err != nil {
						t.Log("Error fetching keys", err)
						return 0
					}
					return len(items)
				}).ShouldEqual(time.Second*30, time.Second, 0)
				if !ok {
					t.Fatalf("Provider %s does not have zero keys", name)
				}
			}

			// The leader should pass mesh storage conformance.
			t.Run("LeaderConformance", func(t *testing.T) {
				TestMeshStorageConformance(ctx, t, leader.MeshStorage())
			})
		}

		t.Run("ThreeVoters", func(t *testing.T) {
			runTest(t, MustAddVoter)
		})

		// Same test as above but with one voter and two observers.
		t.Run("OneVoterTwoObservers", func(t *testing.T) {
			if os.Getenv("CI") == "true" {
				// Only do the Voter test on CI to save time
				t.Skip("Skipping test on CI")
			}
			runTest(t, MustAddObserver)
		})
	})
}
