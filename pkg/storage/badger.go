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

package storage

import (
	"fmt"
	"io"

	"github.com/dgraph-io/badger/v4"
)

type badgerStorage struct {
	db *badger.DB
}

func newBadgerStorage(opts *Options) (Storage, error) {
	var badgeropts badger.Options
	if opts.InMemory {
		badgeropts = badger.DefaultOptions("").WithInMemory(true)
	} else {
		badgeropts = badger.DefaultOptions(opts.DiskPath)
	}
	db, err := badger.Open(badgeropts)
	if err != nil {
		return nil, fmt.Errorf("badger open: %w", err)
	}
	return &badgerStorage{db}, nil
}

// Get returns the value of a key.
func (b *badgerStorage) Get(key string) (string, error) {
	return "", nil
}

// Put sets the value of a key.
func (b *badgerStorage) Put(key, value string) error {
	return nil
}

// Delete removes a key.
func (b *badgerStorage) Delete(key string) error {
	return nil
}

// List returns all keys with a given prefix.
func (b *badgerStorage) List(prefix string) ([]string, error) {
	return nil, nil
}

// Snapshot returns a snapshot of the storage.
func (b *badgerStorage) Snapshot() (io.ReadCloser, error) {
	return nil, nil
}

// Restore restores a snapshot of the storage.
func (b *badgerStorage) Restore(r io.Reader) error {
	return nil
}

// Close closes the storage.
func (b *badgerStorage) Close() error {
	return b.db.Close()
}
