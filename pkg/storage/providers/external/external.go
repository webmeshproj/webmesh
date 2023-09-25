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

// Package external provides a storage provider that uses a storage plugin
// to manage mesh storage and consensus.
package external

import (
	"context"
	"fmt"
	"io"
	"time"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/storage"
)

// Ensure we satisfy the provider interface.
var _ storage.Provider = &ExternalStorageProvider{}
var _ storage.Consensus = &ExternalConsensus{}
var _ storage.MeshStorage = &ExternalStorage{}

// Options are the options for the external storage provider.
type Options struct{}

// ExternalStorageProvider is a storage provider that uses a storage plugin.
type ExternalStorageProvider struct {
	Options
}

// NewStorageProvider returns a new ExternalStorageProvider.
func NewStorageProvider(opts Options) *ExternalStorageProvider {
	return &ExternalStorageProvider{Options: opts}
}

// Storage returns the underlying MeshStorage instance. The provider does not need to
// guarantee consistency on read operations.
func (ext *ExternalStorageProvider) Storage() storage.MeshStorage {
	return &ExternalStorage{ext}
}

// Consensus returns the underlying Consensus instance.
func (ext *ExternalStorageProvider) Consensus() storage.Consensus {
	return &ExternalConsensus{ext}
}

// Start should start the provider and any resources that it may need.
func (ext *ExternalStorageProvider) Start(context.Context) error {
	return fmt.Errorf("not implemented")
}

// Bootstrap should bootstrap the provider for first-time usage.
func (ext *ExternalStorageProvider) Bootstrap(context.Context) error {
	return fmt.Errorf("not implemented")
}

// Status returns the status of the storage provider.
func (ext *ExternalStorageProvider) Status() *v1.StorageStatus {
	return &v1.StorageStatus{
		Message: "not implemented",
	}
}

// Close should close the underlying storage as well as any other resources that the provider may have allocated.
func (ext *ExternalStorageProvider) Close() error {
	return fmt.Errorf("not implemented")
}

// ExternalConsensus is a consensus implementation that uses a storage plugin.
type ExternalConsensus struct {
	*ExternalStorageProvider
}

// IsLeader returns true if the node is the leader of the storage group.
func (ext *ExternalConsensus) IsLeader() bool {
	return false
}

// AddVoter adds a voter to the consensus group.
func (ext *ExternalConsensus) AddVoter(context.Context, *v1.StoragePeer) error {
	return fmt.Errorf("not implemented")
}

// AddObserver adds an observer to the consensus group.
func (ext *ExternalConsensus) AddObserver(context.Context, *v1.StoragePeer) error {
	return fmt.Errorf("not implemented")
}

// DemoteVoter demotes a voter to an observer.
func (ext *ExternalConsensus) DemoteVoter(context.Context, *v1.StoragePeer) error {
	return fmt.Errorf("not implemented")
}

// RemovePeer removes a peer from the consensus group. If wait
// is true, the function will wait for the peer to be removed.
func (ext *ExternalConsensus) RemovePeer(ctx context.Context, peer *v1.StoragePeer, wait bool) error {
	return fmt.Errorf("not implemented")
}

// ExternalStorage is a storage implementation that uses a storage plugin.
type ExternalStorage struct {
	*ExternalStorageProvider
}

// GetValue returns the value of a key.
func (ext *ExternalStorage) GetValue(ctx context.Context, key string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

// PutValue sets the value of a key. TTL is optional and can be set to 0.
func (ext *ExternalStorage) PutValue(ctx context.Context, key, value string, ttl time.Duration) error {
	return fmt.Errorf("not implemented")
}

// Delete removes a key.
func (ext *ExternalStorage) Delete(ctx context.Context, key string) error {
	return fmt.Errorf("not implemented")
}

// List returns all keys with a given prefix.
func (ext *ExternalStorage) List(ctx context.Context, prefix string) ([]string, error) {
	return nil, fmt.Errorf("not implemented")
}

// IterPrefix iterates over all keys with a given prefix. It is important
// that the iterator not attempt any write operations as this will cause
// a deadlock. The iteration will stop if the iterator returns an error.
func (ext *ExternalStorage) IterPrefix(ctx context.Context, prefix string, fn storage.PrefixIterator) error {
	return fmt.Errorf("not implemented")
}

// Snapshot returns a snapshot of the storage.
func (ext *ExternalStorage) Snapshot(ctx context.Context) (io.Reader, error) {
	return nil, fmt.Errorf("not implemented")
}

// Restore restores a snapshot of the storage.
func (ext *ExternalStorage) Restore(ctx context.Context, r io.Reader) error {
	return fmt.Errorf("not implemented")
}

// Subscribe will call the given function whenever a key with the given prefix is changed.
// The returned function can be called to unsubscribe.
func (ext *ExternalStorage) Subscribe(ctx context.Context, prefix string, fn storage.SubscribeFunc) (context.CancelFunc, error) {
	return func() {}, fmt.Errorf("not implemented")
}
