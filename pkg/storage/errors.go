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
	"errors"
	"fmt"
)

// Common errors for storage providers to use.
var (
	// ErrNotStorageNode is returned when a storage operation is attempted on a non-storage node.
	ErrNotStorageNode = fmt.Errorf("not a storage node")
	// ErrStarted is returned when the storage provider is already started.
	ErrStarted = fmt.Errorf("storage provider already started")
	// ErrClosed is returned when the storage provider is closed.
	ErrClosed = fmt.Errorf("storage provider is closed")
	// ErrNotImplemented is returned when a method is not implemented.
	ErrNotImplemented = fmt.Errorf("not implemented")
	// ErrNoLeader is returned when there is no leader.
	ErrNoLeader = fmt.Errorf("no leader")
	// ErrNotLeader is returned when the node is not the leader.
	ErrNotLeader = fmt.Errorf("not leader")
	// ErrNotVoter is returned when the node is not a voter.
	ErrNotVoter = fmt.Errorf("not voter")
	// ErrAlreadyBootstrapped is returned when the storage provider is already bootstrapped.
	ErrAlreadyBootstrapped = fmt.Errorf("already bootstrapped")
	// ErrKeyNotFound is the error returned when a key is not found.
	ErrKeyNotFound = errors.New("key not found")
	// ErrInvalidKey is the error returned when a key is invalid.
	ErrInvalidKey = errors.New("invalid key")
	// ErrInvalidPrefix is the error returned when a prefix is invalid.
	ErrInvalidPrefix = errors.New("invalid prefix")
)

// NewKeyNotFoundError returns a new ErrKeyNotFound error.
func NewKeyNotFoundError(key []byte) error {
	return fmt.Errorf("%w: %s", ErrKeyNotFound, string(key))
}

// IsKeyNotFoundError returns true if the given error is a ErrKeyNotFound error.
func IsKeyNotFoundError(err error) bool {
	return errors.Is(err, ErrKeyNotFound)
}
