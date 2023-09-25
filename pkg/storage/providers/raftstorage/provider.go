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

// Package raftstorage implements a Raft-backed storage provider.
package raftstorage

import (
	"context"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/storage"
)

// Ensure we satisfy the provider interface.
var _ storage.Provider = &RaftStorageProvider{}

// RaftStorage is a storage provider that uses Raft for consensus.
// BadgerDB is used for the underlying storage.
type RaftStorageProvider struct{}

// Storage returns the underlying MeshStorage instance.
func (r *RaftStorageProvider) Storage() storage.MeshStorage { return nil }

// Consensus returns the underlying Consensus instance.
func (r *RaftStorageProvider) Consensus() storage.Consensus { return nil }

// Status returns the status of the storage provider.
func (r *RaftStorageProvider) Status() *v1.StorageStatus { return nil }

// Start starts the raft storage provider.
func (r *RaftStorageProvider) Start(ctx context.Context) error { return nil }

// Bootstrap bootstraps the raft storage provider.
func (r *RaftStorageProvider) Bootstrap(ctx context.Context) error { return nil }

// Close closes the mesh storage and shuts down the raft instance.
func (r *RaftStorageProvider) Close() error { return nil }
