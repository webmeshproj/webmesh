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

	t.Run("TestThreeVoterConformance", func(t *testing.T) {
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
		// Add the others as voters.
		for _, provider := range []storage.Provider{providers["provider2"], providers["provider3"]} {
			// Add each provider as a voter to the consensus group.
			MustAddVoter(ctx, t, providers["provider1"], provider)
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
		// We should be able to write keys to the leader and have them propagate to the followers.
	})
}
