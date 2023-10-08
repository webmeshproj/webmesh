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

// Package errors contains error definitions for storage providers.
package errors

import (
	"errors"
	"fmt"

	"github.com/dominikbraun/graph"
)

// Is is a shortcut for errors.Is.
var Is = errors.Is

// Common errors for storage providers to use.
var (
	// ErrNodeNotFound is returned when a node is not found.
	ErrNodeNotFound = errors.New("node not found")
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
	// ErrNotFound is an alias to ErrKeyNotFound
	ErrNotFound = ErrKeyNotFound
	// ErrInvalidKey is the error returned when a key is invalid.
	ErrInvalidKey = errors.New("invalid key")
	// ErrInvalidPrefix is the error returned when a prefix is invalid.
	ErrInvalidPrefix = errors.New("invalid prefix")
	// ErrEdgeNotFound is returned when an edge is not found.
	ErrEdgeNotFound = graph.ErrEdgeNotFound
	// ErrRoleNotFound is returned when a role is not found.
	ErrRoleNotFound = fmt.Errorf("role not found")
	// ErrRoleBindingNotFound is returned when a rolebinding is not found.
	ErrRoleBindingNotFound = fmt.Errorf("rolebinding not found")
	// ErrGroupNotFound is returned when a group is not found.
	ErrGroupNotFound = fmt.Errorf("group not found")
	// ErrIsSystemRole is returned when a system role is being modified.
	ErrIsSystemRole = fmt.Errorf("cannot modify system role")
	// ErrIsSystemRoleBinding is returned when a system rolebinding is being modified.
	ErrIsSystemRoleBinding = fmt.Errorf("cannot modify system rolebinding")
	// ErrIsSystemGroup is returned when a system group is being modified.
	ErrIsSystemGroup = fmt.Errorf("cannot modify system group")
	// ErrACLNotFound is returned when a NetworkACL is not found.
	ErrACLNotFound = errors.New("network acl not found")
	// ErrRouteNotFound is returned when a Route is not found.
	ErrRouteNotFound = errors.New("route not found")
	// ErrInvalidACL is returned when a NetworkACL is invalid.
	ErrInvalidACL = errors.New("invalid network acl")
	// ErrInvalidRoute is returned when a Route is invalid.
	ErrInvalidRoute = errors.New("invalid route")
	// ErrEmptyNodeID is returned when a node ID is empty.
	ErrEmptyNodeID = errors.New("node ID must not be empty")
	// ErrInvalidNodeID is returned when a node ID is invalid.
	ErrInvalidNodeID = errors.New("node ID is invalid")
	// ErrInvalidQuery is returned when a query is invalid.
	ErrInvalidQuery = errors.New("invalid query")
)

// NewKeyNotFoundError returns a new ErrKeyNotFound error.
func NewKeyNotFoundError(key []byte) error {
	return fmt.Errorf("%w: %s", ErrKeyNotFound, string(key))
}

// IsNotFound returns if the error matches any of the known not found errors.
func IsNotFound(err error) bool {
	return IsKeyNotFound(err) ||
		IsNodeNotFound(err) ||
		IsEdgeNotFound(err) ||
		IsRoleNotFound(err) ||
		IsRoleBindingNotFound(err) ||
		IsGroupNotFound(err) ||
		IsACLNotFound(err) ||
		IsRouteNotFound(err)
}

// IsKeyNotFoundError returns true if the given error is a ErrKeyNotFound error.
func IsKeyNotFound(err error) bool {
	return Is(err, ErrKeyNotFound)
}

// IsNodeNotFound returns true if the given error is a ErrNodeNotFound error.
func IsNodeNotFound(err error) bool {
	return Is(err, ErrNodeNotFound)
}

// IsAlreadyBootstrappedError returns true if the given error is a ErrAlreadyBootstrapped error.
func IsAlreadyBootstrapped(err error) bool {
	return Is(err, ErrAlreadyBootstrapped)
}

// IsInvalidACL returns true if the given error is a ErrInvalidACL error.
func IsInvalidACL(err error) bool {
	return Is(err, ErrInvalidACL)
}

// IsACLNotFound returns true if the given error is a ErrACLNotFound error.
func IsACLNotFound(err error) bool {
	return Is(err, ErrACLNotFound)
}

// IsInvalidRoute returns true if the given error is a ErrInvalidRoute error.
func IsInvalidRoute(err error) bool {
	return Is(err, ErrInvalidRoute)
}

// IsRouteNotFound returns true if the given error is a ErrRouteNotFound error.
func IsRouteNotFound(err error) bool {
	return Is(err, ErrRouteNotFound)
}

// IsEdgeNotFound returns true if the given error is a ErrEdgeNotFound error.
func IsEdgeNotFound(err error) bool {
	return Is(err, ErrEdgeNotFound)
}

// IsRoleNotFound returns true if the given error is a ErrRoleNotFound error.
func IsRoleNotFound(err error) bool {
	return Is(err, ErrRoleNotFound)
}

// IsRoleBindingNotFound returns true if the given error is a ErrRoleBindingNotFound error.
func IsRoleBindingNotFound(err error) bool {
	return Is(err, ErrRoleBindingNotFound)
}

// IsGroupNotFoundError returns true if the given error is a ErrGroupNotFound error.
func IsGroupNotFound(err error) bool {
	return Is(err, ErrGroupNotFound)
}

// IsNoLeader returns true if the given error is a ErrNoLeader error.
func IsNoLeader(err error) bool {
	return Is(err, ErrNoLeader)
}
