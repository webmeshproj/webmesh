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
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// Ensure we satisfy the provider interface.
var _ storage.Provider = &ExternalStorageProvider{}
var _ storage.Consensus = &ExternalConsensus{}
var _ storage.MeshStorage = &ExternalStorage{}

// Options are the options for the external storage provider.
type Options struct {
	// NodeID is the ID of the node.
	NodeID string
	// Config is the configuration for the storage provider plugin.
	Config *v1.PluginConfiguration
	// Server is the address of a server for the storage provider.
	Server string
	// TLSConfig is the TLS configuration for the storage provider.
	TLSConfig *tls.Config
	// LogLevel is the log level for the storage provider.
	LogLevel string
}

// ExternalStorageProvider is a storage provider that uses a storage plugin.
type ExternalStorageProvider struct {
	Options
	cli  v1.StorageProviderPluginClient
	conn *grpc.ClientConn
	log  *slog.Logger
	mu   sync.Mutex
}

// NewStorageProvider returns a new ExternalStorageProvider.
func NewStorageProvider(opts Options) *ExternalStorageProvider {
	return &ExternalStorageProvider{
		Options: opts,
		log:     logging.NewLogger(opts.LogLevel).With("component", "storage-provider", "provider", "external"),
	}
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
func (ext *ExternalStorageProvider) Start(ctx context.Context) error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.conn != nil {
		return storage.ErrStarted
	}
	var opts []grpc.DialOption
	if ext.TLSConfig != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(ext.TLSConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	c, err := grpc.DialContext(ctx, ext.Options.Server, opts...)
	if err != nil {
		return fmt.Errorf("dial storage provider: %w", err)
	}
	ext.conn = c
	ext.cli = v1.NewStorageProviderPluginClient(c)
	_, err = v1.NewPluginClient(c).Configure(ctx, ext.Options.Config)
	if err != nil {
		return fmt.Errorf("configure plugin: %w", err)
	}
	return nil
}

// Bootstrap should bootstrap the provider for first-time usage.
func (ext *ExternalStorageProvider) Bootstrap(ctx context.Context) error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return storage.ErrClosed
	}
	_, err := ext.cli.Bootstrap(ctx, &v1.BootstrapRequest{})
	if err != nil {
		if status.Code(err) == codes.FailedPrecondition {
			return storage.ErrAlreadyBootstrapped
		}
		return fmt.Errorf("bootstrap: %w", err)
	}
	return nil
}

// Status returns the status of the storage provider.
func (ext *ExternalStorageProvider) Status() *v1.StorageStatus {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return &v1.StorageStatus{
			Message: storage.ErrClosed.Error(),
		}
	}
	status, err := ext.cli.GetStatus(context.Background(), &v1.StorageStatusRequest{})
	if err != nil {
		return &v1.StorageStatus{
			Message: err.Error(),
		}
	}
	return status
}

// Close should close the underlying storage as well as any other resources that the provider may have allocated.
func (ext *ExternalStorageProvider) Close() error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.conn == nil {
		return storage.ErrClosed
	}
	defer func() {
		err := ext.conn.Close()
		if err != nil {
			ext.log.Error("Failed to close storage provider", "error", err.Error())
		}
		ext.conn = nil
	}()
	_, err := v1.NewPluginClient(ext.conn).Close(context.Background(), &emptypb.Empty{})
	if err != nil {
		return fmt.Errorf("close plugin: %w", err)
	}
	return nil
}

// ExternalConsensus is a consensus implementation that uses a storage plugin.
type ExternalConsensus struct {
	*ExternalStorageProvider
}

// IsLeader returns true if the node is the leader of the storage group.
func (ext *ExternalConsensus) IsLeader() bool {
	// Use a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	leader, err := ext.cli.GetLeader(ctx, &v1.GetLeaderRequest{})
	if err != nil {
		ext.log.Error("Failed to get leader", "error", err.Error())
		return false
	}
	return leader.GetId() == ext.NodeID
}

// AddVoter adds a voter to the consensus group.
func (ext *ExternalConsensus) AddVoter(ctx context.Context, peer *v1.StoragePeer) error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return storage.ErrClosed
	}
	_, err := ext.cli.AddVoter(ctx, peer)
	if err != nil {
		return fmt.Errorf("add voter: %w", err)
	}
	return nil
}

// AddObserver adds an observer to the consensus group.
func (ext *ExternalConsensus) AddObserver(ctx context.Context, peer *v1.StoragePeer) error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return storage.ErrClosed
	}
	_, err := ext.cli.AddObserver(ctx, peer)
	if err != nil {
		return fmt.Errorf("add observer: %w", err)
	}
	return nil
}

// DemoteVoter demotes a voter to an observer.
func (ext *ExternalConsensus) DemoteVoter(ctx context.Context, peer *v1.StoragePeer) error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return storage.ErrClosed
	}
	_, err := ext.cli.DemoteVoter(ctx, peer)
	if err != nil {
		return fmt.Errorf("demote voter: %w", err)
	}
	return nil
}

// RemovePeer removes a peer from the consensus group. If wait
// is true, the function will wait for the peer to be removed.
func (ext *ExternalConsensus) RemovePeer(ctx context.Context, peer *v1.StoragePeer, wait bool) error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return storage.ErrClosed
	}
	_, err := ext.cli.RemovePeer(ctx, peer)
	if err != nil {
		return fmt.Errorf("remove peer: %w", err)
	}
	return nil
}

// ExternalStorage is a storage implementation that uses a storage plugin.
type ExternalStorage struct {
	*ExternalStorageProvider
}

// GetValue returns the value of a key.
func (ext *ExternalStorage) GetValue(ctx context.Context, key string) (string, error) {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return "", storage.ErrClosed
	}
	return "", storage.ErrNotImplemented
}

// PutValue sets the value of a key. TTL is optional and can be set to 0.
func (ext *ExternalStorage) PutValue(ctx context.Context, key, value string, ttl time.Duration) error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return storage.ErrClosed
	}
	return storage.ErrNotImplemented
}

// Delete removes a key.
func (ext *ExternalStorage) Delete(ctx context.Context, key string) error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return storage.ErrClosed
	}
	return storage.ErrNotImplemented
}

// List returns all keys with a given prefix.
func (ext *ExternalStorage) List(ctx context.Context, prefix string) ([]string, error) {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return nil, storage.ErrClosed
	}
	return nil, storage.ErrNotImplemented
}

// IterPrefix iterates over all keys with a given prefix. It is important
// that the iterator not attempt any write operations as this will cause
// a deadlock. The iteration will stop if the iterator returns an error.
func (ext *ExternalStorage) IterPrefix(ctx context.Context, prefix string, fn storage.PrefixIterator) error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return storage.ErrClosed
	}
	return storage.ErrNotImplemented
}

// Snapshot returns a snapshot of the storage.
func (ext *ExternalStorage) Snapshot(ctx context.Context) (io.Reader, error) {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return nil, storage.ErrClosed
	}
	return nil, storage.ErrNotImplemented
}

// Restore restores a snapshot of the storage.
func (ext *ExternalStorage) Restore(ctx context.Context, r io.Reader) error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return storage.ErrClosed
	}
	return storage.ErrNotImplemented
}

// Subscribe will call the given function whenever a key with the given prefix is changed.
// The returned function can be called to unsubscribe.
func (ext *ExternalStorage) Subscribe(ctx context.Context, prefix string, fn storage.SubscribeFunc) (context.CancelFunc, error) {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return func() {}, storage.ErrClosed
	}
	return func() {}, storage.ErrNotImplemented
}
