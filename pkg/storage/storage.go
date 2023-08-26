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
// about the state of the mesh.
package storage

import (
	"context"
	"errors"
	"io"
	"time"
)

// Storage is the interface for storing and retrieving data about the state of the mesh.
type Storage interface {
	// Get returns the value of a key.
	Get(ctx context.Context, key string) (string, error)
	// Put sets the value of a key. TTL is optional and can be set to 0.
	Put(ctx context.Context, key, value string, ttl time.Duration) error
	// Delete removes a key.
	Delete(ctx context.Context, key string) error
	// List returns all keys with a given prefix.
	List(ctx context.Context, prefix string) ([]string, error)
	// IterPrefix iterates over all keys with a given prefix. It is important
	// that the iterator not attempt any write operations as this will cause
	// a deadlock.
	IterPrefix(ctx context.Context, prefix string, fn PrefixIterator) error
	// Snapshot returns a snapshot of the storage.
	Snapshot(ctx context.Context) (io.Reader, error)
	// Restore restores a snapshot of the storage.
	Restore(ctx context.Context, r io.Reader) error
	// Subscribe will call the given function whenever a key with the given prefix is changed.
	// The returned function can be called to unsubscribe.
	Subscribe(ctx context.Context, prefix string, fn SubscribeFunc) (func(), error)
	// Close closes the storage.
	Close() error
}

// SubscribeFunc is the function signature for subscribing to changes to a key.
type SubscribeFunc func(key, value string)

// PrefixIterator is the function signature for iterating over all keys with a given prefix.
type PrefixIterator func(key, value string) error

// ErrKeyNotFound is the error returned when a key is not found.
var ErrKeyNotFound = errors.New("key not found")
