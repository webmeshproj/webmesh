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

// diskStorage uses a Badger database on disk.
type diskStorage struct{}

// newDiskStorage returns a new disk storage.
func newDiskStorage(opts *Options) Storage {
	return &diskStorage{}
}

// Get returns the value of a key.
func (dsk *diskStorage) Get(key string) (string, error) {
	return "", nil
}

// Put sets the value of a key.
func (dsk *diskStorage) Put(key, value string) error {
	return nil
}

// Delete removes a key.
func (dsk *diskStorage) Delete(key string) error {
	return nil
}

// List returns all keys with a given prefix.
func (dsk *diskStorage) List(prefix string) ([]string, error) {
	return nil, nil
}

// Snapshot returns a snapshot of the storage.
func (dsk *diskStorage) Snapshot() (io.ReadCloser, error) {
	return nil, nil
}

// Restore restores a snapshot of the storage.
func (dsk *diskStorage) Restore(r io.Reader) error {
	return nil
}

// Close closes the storage.
func (dsk *diskStorage) Close() error {
	return nil
}
