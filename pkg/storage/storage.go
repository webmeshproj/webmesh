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
	"errors"
	"io"
)

// Storage is the interface for storing and retrieving data about the state of the mesh.
type Storage interface {
	// Get returns the value of a key.
	Get(key string) (string, error)
	// Put sets the value of a key.
	Put(key, value string) error
	// Delete removes a key.
	Delete(key string) error
	// List returns all keys with a given prefix.
	List(prefix string) ([]string, error)
	// Snapshot returns a snapshot of the storage.
	Snapshot() (io.ReadCloser, error)
	// Restore restores a snapshot of the storage.
	Restore(r io.Reader) error
	// ReadOnly returns a read-only view of the storage.
	ReadOnly() Storage
	// Close closes the storage.
	Close() error
}

// ErrReadOnly is the error returned when attempting to write to a read-only storage.
var ErrReadOnly = errors.New("read-only storage")

// Options are the options for creating a new Storage.
type Options struct {
	// InMemory specifies whether to use an in-memory storage.
	InMemory bool
	// DiskPath is the path to the disk storage.
	DiskPath string
}

// New returns a new Storage.
func New(opts *Options) (Storage, error) {
	return newBadgerStorage(opts)
}
