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

// Package storage contains the interfaces for storing and retrieving data
// about the state of the mesh and maintaining consensus.
package storage

import (
	"context"
	"io"
	"time"

	"github.com/hashicorp/raft"
)

// MeshStorage is the interface for storing and retrieving data about the state of the mesh.
type MeshStorage interface {
	io.Closer

	// GetValue returns the value of a key.
	GetValue(ctx context.Context, key []byte) ([]byte, error)
	// PutValue sets the value of a key. TTL is optional and can be set to 0.
	PutValue(ctx context.Context, key, value []byte, ttl time.Duration) error
	// Delete removes a key.
	Delete(ctx context.Context, key []byte) error
	// ListKeys returns all keys with a given prefix.
	ListKeys(ctx context.Context, prefix []byte) ([][]byte, error)
	// IterPrefix iterates over all keys with a given prefix. It is important
	// that the iterator not attempt any write operations as this will cause
	// a deadlock. The iteration will stop if the iterator returns an error.
	IterPrefix(ctx context.Context, prefix []byte, fn PrefixIterator) error
	// Subscribe will call the given function whenever a key with the given prefix is changed.
	// The returned function can be called to unsubscribe.
	Subscribe(ctx context.Context, prefix []byte, fn SubscribeFunc) (context.CancelFunc, error)
}

// ConsensusStorage is the interface for storing and retrieving data about the state of consensus.
// This is currently only used by the built-in raftstorage implementation.
type ConsensusStorage interface {
	io.Closer
	raft.LogStore
	raft.StableStore

	// Snapshot returns a snapshot of the storage.
	Snapshot(ctx context.Context) (io.Reader, error)
	// Restore restores a snapshot of the storage.
	Restore(ctx context.Context, r io.Reader) error
}

// SubscribeFunc is the function signature for subscribing to changes to a key.
type SubscribeFunc func(key, value []byte)

// PrefixIterator is the function signature for iterating over all keys with a given prefix.
type PrefixIterator func(key, value []byte) error

// DualStorage represents a storage interface that can serve as both a mesh and consensus storage.
type DualStorage interface {
	MeshStorage
	ConsensusStorage
}
