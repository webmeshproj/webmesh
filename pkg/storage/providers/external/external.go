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
	"net/netip"
	"sync"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/storageutil"
)

// Ensure we satisfy the provider interface.
var _ storage.Provider = &Provider{}
var _ storage.Consensus = &Consensus{}
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

// Provider is a storage provider that uses a storage plugin.
type Provider struct {
	Options
	storage   storage.MeshStorage
	consensus storage.Consensus
	cli       v1.StorageProviderPluginClient
	conn      *grpc.ClientConn
	log       *slog.Logger
	mu        sync.RWMutex
}

// NewProvider returns a new ExternalStorageProvider.
func NewProvider(opts Options) *Provider {
	p := &Provider{
		Options: opts,
		log:     logging.NewLogger(opts.LogLevel).With("component", "storage-provider", "provider", "external"),
	}
	p.storage = &ExternalStorage{p}
	p.consensus = &Consensus{p}
	return p
}

// MeshStorage returns the underlying MeshStorage instance. The provider does not need to
// guarantee consistency on read operations.
func (ext *Provider) MeshStorage() storage.MeshStorage {
	return ext.storage
}

// Consensus returns the underlying Consensus instance.
func (ext *Provider) Consensus() storage.Consensus {
	return ext.consensus
}

// Start should start the provider and any resources that it may need.
func (ext *Provider) Start(ctx context.Context) error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.conn != nil {
		return errors.ErrStarted
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
	if ext.Options.Config == nil {
		ext.Options.Config = &v1.PluginConfiguration{}
	}
	_, err = v1.NewPluginClient(c).Configure(ctx, ext.Options.Config)
	if err != nil {
		return fmt.Errorf("configure plugin: %w", err)
	}
	return nil
}

// Bootstrap should bootstrap the provider for first-time usage.
func (ext *Provider) Bootstrap(ctx context.Context) error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return errors.ErrClosed
	}
	_, err := ext.cli.Bootstrap(ctx, &v1.BootstrapRequest{})
	if err != nil {
		if status.Code(err) == codes.FailedPrecondition {
			return errors.ErrAlreadyBootstrapped
		}
		return fmt.Errorf("bootstrap: %w", err)
	}
	return nil
}

// ListenPort attempts to return the TCP port that the storage provider is listening on.
func (ext *Provider) ListenPort() uint16 {
	status := ext.Status()
	for _, peer := range status.GetPeers() {
		if peer.GetId() == ext.NodeID {
			addrport, err := netip.ParseAddrPort(peer.GetAddress())
			if err != nil {
				ext.log.Error("Failed to parse peer address", "error", err.Error())
				return 0
			}
			return addrport.Port()
		}
	}
	return 0
}

// Status returns the status of the storage provider.
func (ext *Provider) Status() *v1.StorageStatus {
	ext.mu.RLock()
	defer ext.mu.RUnlock()
	if ext.cli == nil {
		return &v1.StorageStatus{
			Message: errors.ErrClosed.Error(),
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
func (ext *Provider) Close() error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.conn == nil {
		return errors.ErrClosed
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

// Consensus is a consensus implementation that uses a storage plugin.
type Consensus struct {
	*Provider
}

// IsLeader returns true if the node is the leader of the storage group.
func (ext *Consensus) IsLeader() bool {
	// Use a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	leader, err := ext.GetLeader(ctx)
	if err != nil {
		ext.log.Error("Failed to get leader", "error", err.Error())
		return false
	}
	return leader.GetId() == ext.NodeID
}

// IsMember returns true if the node is a member of the storage group.
// External storage providers should always be members.
func (ext *Consensus) IsMember() bool {
	return true
}

// GetPeers returns the peers of the storage group.
func (ext *Consensus) GetPeers(ctx context.Context) ([]*v1.StoragePeer, error) {
	ext.mu.RLock()
	defer ext.mu.RUnlock()
	if ext.cli == nil {
		return nil, errors.ErrClosed
	}
	resp, err := ext.cli.GetPeers(ctx, &v1.GetPeersRequest{})
	if err != nil {
		return nil, fmt.Errorf("get peers: %w", err)
	}
	return resp.GetPeers(), nil
}

// GetLeader returns the leader of the storage group.
func (ext *Consensus) GetLeader(ctx context.Context) (*v1.StoragePeer, error) {
	ext.mu.RLock()
	defer ext.mu.RUnlock()
	if ext.cli == nil {
		return nil, errors.ErrClosed
	}
	leader, err := ext.cli.GetLeader(ctx, &v1.GetLeaderRequest{})
	if err != nil {
		return nil, fmt.Errorf("get leader: %w", err)
	}
	return leader, nil
}

// AddVoter adds a voter to the consensus group.
func (ext *Consensus) AddVoter(ctx context.Context, peer *v1.StoragePeer) error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return errors.ErrClosed
	}
	_, err := ext.cli.AddVoter(ctx, peer)
	if err != nil {
		if status.Code(err) == codes.FailedPrecondition {
			return errors.ErrNotLeader
		}
		return fmt.Errorf("add voter: %w", err)
	}
	return nil
}

// AddObserver adds an observer to the consensus group.
func (ext *Consensus) AddObserver(ctx context.Context, peer *v1.StoragePeer) error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return errors.ErrClosed
	}
	_, err := ext.cli.AddObserver(ctx, peer)
	if err != nil {
		if status.Code(err) == codes.FailedPrecondition {
			return errors.ErrNotLeader
		}
		return fmt.Errorf("add observer: %w", err)
	}
	return nil
}

// DemoteVoter demotes a voter to an observer.
func (ext *Consensus) DemoteVoter(ctx context.Context, peer *v1.StoragePeer) error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return errors.ErrClosed
	}
	_, err := ext.cli.DemoteVoter(ctx, peer)
	if err != nil {
		if status.Code(err) == codes.FailedPrecondition {
			return errors.ErrNotLeader
		}
		return fmt.Errorf("demote voter: %w", err)
	}
	return nil
}

// RemovePeer removes a peer from the consensus group. If wait
// is true, the function will wait for the peer to be removed.
func (ext *Consensus) RemovePeer(ctx context.Context, peer *v1.StoragePeer, wait bool) error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return errors.ErrClosed
	}
	_, err := ext.cli.RemovePeer(ctx, peer)
	if err != nil {
		if status.Code(err) == codes.FailedPrecondition {
			return errors.ErrNotLeader
		}
		return fmt.Errorf("remove peer: %w", err)
	}
	return nil
}

// ExternalStorage is a storage implementation that uses a storage plugin.
type ExternalStorage struct {
	*Provider
}

// GetValue returns the value of a key.
func (ext *ExternalStorage) GetValue(ctx context.Context, key []byte) ([]byte, error) {
	ext.mu.RLock()
	defer ext.mu.RUnlock()
	if ext.cli == nil {
		return nil, errors.ErrClosed
	}
	if !storageutil.IsValidKey(string(key)) {
		return nil, errors.ErrInvalidKey
	}
	resp, err := ext.cli.GetValue(ctx, &v1.GetValueRequest{Key: key})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, errors.ErrKeyNotFound
		}
		return nil, fmt.Errorf("get value: %w", err)
	}
	return resp.GetValue().GetValue(), nil
}

// PutValue sets the value of a key. TTL is optional and can be set to 0.
func (ext *ExternalStorage) PutValue(ctx context.Context, key, value []byte, ttl time.Duration) error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return errors.ErrClosed
	}
	if !storageutil.IsValidKey(string(key)) {
		return errors.ErrInvalidKey
	}
	_, err := ext.cli.PutValue(ctx, &v1.PutValueRequest{
		Value: &v1.StorageValue{
			Key:   key,
			Value: value,
		},
		Ttl: durationpb.New(ttl),
	})
	if err != nil {
		if status.Code(err) == codes.FailedPrecondition {
			return errors.ErrNotVoter
		}
		return fmt.Errorf("put value: %w", err)
	}
	return nil
}

// Delete removes a key.
func (ext *ExternalStorage) Delete(ctx context.Context, key []byte) error {
	ext.mu.Lock()
	defer ext.mu.Unlock()
	if ext.cli == nil {
		return errors.ErrClosed
	}
	if !storageutil.IsValidKey(string(key)) {
		return errors.ErrInvalidKey
	}
	_, err := ext.cli.DeleteValue(ctx, &v1.DeleteValueRequest{Key: key})
	if err != nil {
		if status.Code(err) == codes.FailedPrecondition {
			return errors.ErrNotVoter
		}
		return fmt.Errorf("delete value: %w", err)
	}
	return nil
}

// ListKeys returns all keys with a given prefix.
func (ext *ExternalStorage) ListKeys(ctx context.Context, prefix []byte) ([][]byte, error) {
	ext.mu.RLock()
	defer ext.mu.RUnlock()
	if ext.cli == nil {
		return nil, errors.ErrClosed
	}
	if !storageutil.IsValidKey(string(prefix)) {
		return nil, errors.ErrInvalidPrefix
	}
	resp, err := ext.cli.ListKeys(ctx, &v1.ListKeysRequest{Prefix: prefix})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, errors.ErrKeyNotFound
		}
		return nil, fmt.Errorf("list keys: %w", err)
	}
	return resp.GetKeys(), nil
}

// IterPrefix iterates over all keys with a given prefix. It is important
// that the iterator not attempt any write operations as this will cause
// a deadlock. The iteration will stop if the iterator returns an error.
func (ext *ExternalStorage) IterPrefix(ctx context.Context, prefix []byte, fn storage.PrefixIterator) error {
	ext.mu.RLock()
	defer ext.mu.RUnlock()
	if ext.cli == nil {
		return errors.ErrClosed
	}
	if !storageutil.IsValidKey(string(prefix)) {
		return errors.ErrInvalidPrefix
	}
	resp, err := ext.cli.ListValues(ctx, &v1.ListValuesRequest{Prefix: prefix})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return errors.ErrKeyNotFound
		}
		return fmt.Errorf("list values: %w", err)
	}
	for _, value := range resp.GetValues() {
		if err := fn(value.GetKey(), value.GetValue()); err != nil {
			return err
		}
	}
	return nil
}

// Subscribe will call the given function whenever a key with the given prefix is changed.
// The returned function can be called to unsubscribe.
func (ext *ExternalStorage) Subscribe(ctx context.Context, prefix []byte, fn storage.SubscribeFunc) (context.CancelFunc, error) {
	ext.mu.RLock()
	defer ext.mu.RUnlock()
	if ext.cli == nil {
		return func() {}, errors.ErrClosed
	}
	if !storageutil.IsValidKey(string(prefix)) {
		return func() {}, errors.ErrInvalidPrefix
	}
	ctx, cancel := context.WithCancel(ctx)
	stream, err := ext.cli.SubscribePrefix(ctx, &v1.SubscribePrefixRequest{Prefix: prefix})
	if err != nil {
		defer cancel()
		return func() {}, fmt.Errorf("subscribe prefix: %w", err)
	}
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				if status.Code(err) == codes.Canceled {
					return
				} else if status.Code(err) == codes.Unavailable {
					ext.log.Error("Storage provider is unavailable", "error", err.Error())
					return
				} else if errors.Is(err, io.EOF) {
					ext.log.Error("Storage provider closed connection", "error", err.Error())
					return
				}
				ext.log.Error("Failed to receive subscription message", "error", err.Error())
				continue
			}
			switch msg.GetEventType() {
			case v1.PrefixEvent_EventTypeRemoved:
				fn(msg.GetValue().GetKey(), nil)
			case v1.PrefixEvent_EventTypeUpdated:
				fn(msg.GetValue().GetKey(), msg.GetValue().GetValue())
			}
		}
	}()
	return cancel, nil
}
