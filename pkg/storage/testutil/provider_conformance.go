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

	"github.com/webmeshproj/webmesh/pkg/storage"
)

// NewProviderFunc is a function that returns a new started storage provider.
// It should have unique identifying properties for each call and not be
// bootstrapped.
type NewProviderFunc func(t *testing.T) storage.Provider

// TestStorageProviderConformance tests that the storage provider conforms to the
// storage provider interface.
func TestStorageProviderConformance(t *testing.T, newProvider NewProviderFunc) {
	ctx := context.Background()

	t.Run("TestStorageConformance", func(t *testing.T) {
		provider := newProvider(t)
		defer provider.Close()
		err := provider.Bootstrap(ctx)
		if err != nil {
			t.Fatalf("Failed to bootstrap provider: %v", err)
		}
		TestMeshStorageConformance(t, provider.MeshStorage())
	})
}
