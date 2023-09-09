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

// Package storage contains the interface for storing and retrieving data
// about the state of the mesh and providing storage backends for raft.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hashicorp/raft"
)

// DualStorage represents a storage interface that can serve as both a mesh and Raft storage.
type DualStorage interface {
	MeshStorage
	RaftStorage
	DropStorage
}

// DropStorage is a storage interface that can be dropped entirely.
// This is primarily used for testing.
type DropStorage interface {
	// DropAll drops all data from the storage. This is primarily used
	// for testing.
	DropAll(ctx context.Context) error
}

// RaftStorage is the interface for storing and retrieving data about the state of the mesh.
// This interface is used by mesh members that are part of the Raft cluster.
type RaftStorage interface {
	raft.LogStore
	raft.StableStore
	DropStorage
	io.Closer
}

// MeshStorage is the interface for storing and retrieving data about the state of the mesh.
type MeshStorage interface {
	DropStorage

	// GetValue returns the value of a key.
	GetValue(ctx context.Context, key string) (string, error)
	// PutValue sets the value of a key. TTL is optional and can be set to 0.
	PutValue(ctx context.Context, key, value string, ttl time.Duration) error
	// Delete removes a key.
	Delete(ctx context.Context, key string) error
	// List returns all keys with a given prefix.
	List(ctx context.Context, prefix string) ([]string, error)
	// IterPrefix iterates over all keys with a given prefix. It is important
	// that the iterator not attempt any write operations as this will cause
	// a deadlock. The iteration will stop if the iterator returns an error.
	IterPrefix(ctx context.Context, prefix string, fn PrefixIterator) error
	// Snapshot returns a snapshot of the storage.
	Snapshot(ctx context.Context) (io.Reader, error)
	// Restore restores a snapshot of the storage.
	Restore(ctx context.Context, r io.Reader) error
	// Subscribe will call the given function whenever a key with the given prefix is changed.
	// The returned function can be called to unsubscribe.
	Subscribe(ctx context.Context, prefix string, fn SubscribeFunc) (context.CancelFunc, error)
	// Close closes the storage.
	Close() error
}

// SubscribeFunc is the function signature for subscribing to changes to a key.
type SubscribeFunc func(key, value string)

// PrefixIterator is the function signature for iterating over all keys with a given prefix.
type PrefixIterator func(key, value string) error

// ErrKeyNotFound is the error returned when a key is not found.
var ErrKeyNotFound = errors.New("key not found")

// NewKeyNotFoundError returns a new ErrKeyNotFound error.
func NewKeyNotFoundError(key string) error {
	return fmt.Errorf("%w: %s", ErrKeyNotFound, key)
}

// IsKeyNotFoundError returns true if the given error is a ErrKeyNotFound error.
func IsKeyNotFoundError(err error) bool {
	return errors.Is(err, ErrKeyNotFound)
}

var reservedPrefixes = []string{
	"/registry/",
	"/raft/",
}

// IsReservedPrefix returns true if the given key is reserved.
func IsReservedPrefix(key string) bool {
	for _, prefix := range reservedPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}
