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

import "io"

// inMemoryStorage uses an in-memory Badger database.
type inMemoryStorage struct{}

// newInMemoryStorage returns a new in-memory storage.
func newInMemoryStorage(opts *Options) Storage {
	return &inMemoryStorage{}
}

// Get returns the value of a key.
func (mem *inMemoryStorage) Get(key string) (string, error) {
	return "", nil
}

// Put sets the value of a key.
func (mem *inMemoryStorage) Put(key, value string) error {
	return nil
}

// Delete removes a key.
func (mem *inMemoryStorage) Delete(key string) error {
	return nil
}

// List returns all keys with a given prefix.
func (mem *inMemoryStorage) List(prefix string) ([]string, error) {
	return nil, nil
}

// Snapshot returns a snapshot of the storage.
func (mem *inMemoryStorage) Snapshot() (io.ReadCloser, error) {
	return nil, nil
}

// Restore restores a snapshot of the storage.
func (mem *inMemoryStorage) Restore(r io.Reader) error {
	return nil
}

// Close closes the storage.
func (mem *inMemoryStorage) Close() error {
	return nil
}
