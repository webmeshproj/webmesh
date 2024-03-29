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

// Package storage defines the interfaces for the storage provider.
package storage

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/go/v1"

	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// Provider is a provider of MeshStorage.
type Provider interface {
	// Close should close the underlying storage as well as any other resources
	// that the provider may have allocated.
	io.Closer
	// Start should start the provider and any resources that it may need.
	Start(context.Context) error
	// Bootstrap should bootstrap the provider for first-time usage.
	Bootstrap(context.Context) error
	// Status returns the status of the storage provider. It should never error.
	// If inaccurate status is available, the node should return itself as a peer
	// with a message describing the inaccuracy.
	Status() *v1.StorageStatus
	// ListenPort should return the TCP port that the storage provider is listening on.
	ListenPort() uint16
	// MeshDB returns the underlying MeshDB instance. The provider does not
	// need to guarantee consistency on read operations.
	MeshDB() MeshDB
	// Consensus returns the underlying Consensus instance for managing voting/observing
	// nodes and leader election.
	Consensus() Consensus
	// MeshStorage returns the underlying raw MeshStorage instance. The provider does
	// not need to guarantee consistency on read operations. This should only be used
	// for arbitrary key/value storage that has not been abstracted behind the MeshDB.
	MeshStorage() MeshStorage
}

// MeshDB is the interface for the mesh database. It provides access to all
// storage interfaces.
type MeshDB interface {
	// MeshDataStore is the underlying MeshDataStore instance.
	MeshDataStore
	// Peers returns a simplified interface for managing nodes in the mesh
	// via the underlying MeshDataStore.
	Peers() Peers
}

// MeshDataStore is an interface for storing and retrieving data about the state of the mesh.
// It can be implemented by external providers to be wrapped into a MeshDB for use throughout
// the library.
type MeshDataStore interface {
	// GraphStore returns the interface for managing network topology and data
	// about peers.
	GraphStore() GraphStore
	// RBAC returns the interface for managing RBAC policies in the mesh.
	RBAC() RBAC
	// MeshState returns the interface for querying mesh state.
	MeshState() MeshState
	// Networking returns the interface for managing networking in the mesh.
	Networking() Networking
}

// Consensus is the interface for managing storage consensus.
type Consensus interface {
	// IsLeader returns true if the node is the leader of the storage group.
	IsLeader() bool
	// IsMember returns true if the node is a member of the storage group.
	IsMember() bool
	// StepDown should be called to relinquish leadership of the storage group.
	StepDown(context.Context) error
	// GetPeer returns the peer with the given ID.
	GetPeer(context.Context, string) (types.StoragePeer, error)
	// GetPeers returns the peers of the storage group.
	GetPeers(context.Context) ([]types.StoragePeer, error)
	// GetLeader returns the leader of the storage group.
	GetLeader(context.Context) (types.StoragePeer, error)
	// AddVoter adds a voter to the consensus group.
	AddVoter(context.Context, types.StoragePeer) error
	// AddObserver adds an observer to the consensus group.
	AddObserver(context.Context, types.StoragePeer) error
	// DemoteVoter demotes a voter to an observer.
	DemoteVoter(context.Context, types.StoragePeer) error
	// RemovePeer removes a peer from the consensus group. If wait
	// is true, the function will wait for the peer to be removed.
	RemovePeer(ctx context.Context, peer types.StoragePeer, wait bool) error
}

// KVSubscribeFunc is the function signature for subscribing to changes to a key.
type KVSubscribeFunc func(key, value []byte)

// PrefixIterator is the function signature for iterating over all keys with a given prefix.
type PrefixIterator func(key, value []byte) error

// ErrStopIteration is a special error that can be returned by PrefixIterator to stop iteration.
var ErrStopIteration = fmt.Errorf("stop iteration")

// MeshStorage is the interface for storing and retrieving data about the state of the mesh.
type MeshStorage interface {
	// Close should close the underlying storage as well as any other resources
	// that the provider may have allocated. This should be called automatically
	// by the provider.
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
	Subscribe(ctx context.Context, prefix []byte, fn KVSubscribeFunc) (context.CancelFunc, error)
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

// DualStorage represents a storage interface that can serve as both mesh and consensus storage.
type DualStorage interface {
	MeshStorage
	ConsensusStorage
}
