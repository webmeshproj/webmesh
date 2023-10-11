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

// Package raftstorage implements a Raft-backed storage provider.
package raftstorage

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/meshdb"
	"github.com/webmeshproj/webmesh/pkg/storage/providers/backends/badgerdb"
	"github.com/webmeshproj/webmesh/pkg/storage/providers/raftstorage/fsm"
)

// Ensure we satisfy the provider interface.
var _ storage.Provider = &Provider{}

// Ensure that RaftStorage implements a MonothonicLogStore.
var _ = raft.MonotonicLogStore(&MonotonicLogStore{})

// MonotonicLogStore is a LogStore that is monotonic.
type MonotonicLogStore struct {
	raft.LogStore
}

// IsMonotonic returns true if the log store is monotonic.
func (m *MonotonicLogStore) IsMonotonic() bool {
	return true
}

type (
	// SnapshotMeta is an alias for raft.SnapshotMeta.
	SnapshotMeta = raft.SnapshotMeta
	// Observation is an alias for raft.Observation.
	Observation = raft.Observation
	// PeerObservation is an alias for raft.PeerObservation.
	PeerObservation = raft.PeerObservation
	// LeaderObservation is an alias for raft.LeaderObservation.
	LeaderObservation = raft.LeaderObservation
)

// ObservationCallback is a callback that can be registered for when an observation
// is received.
type ObservationCallback func(ctx context.Context, obs Observation)

// Raft states.
const (
	Follower  = raft.Follower
	Candidate = raft.Candidate
	Leader    = raft.Leader
	Shutdown  = raft.Shutdown
)

// Raft suffrage states.
const (
	Voter    = raft.Voter
	Nonvoter = raft.Nonvoter
)

// RaftStorage is a storage provider that uses Raft for consensus.
// BadgerDB is used for the underlying storage.
type Provider struct {
	Options
	nodeID                      raft.ServerID
	started                     atomic.Bool
	raft                        *raft.Raft
	raftStorage                 *RaftStorage
	meshDB                      storage.MeshDB
	consensus                   *Consensus
	observer                    *raft.Observer
	observerChan                chan raft.Observation
	observerClose, observerDone chan struct{}
	observerCbs                 []ObservationCallback
	log                         *slog.Logger
	mu                          sync.RWMutex
}

// NewProvider returns a new RaftStorageProvider.
func NewProvider(opts Options) *Provider {
	p := &Provider{
		Options: opts,
		nodeID:  raft.ServerID(opts.NodeID),
		log:     logging.NewLogger(opts.LogLevel, opts.LogFormat).With("component", "raftstorage"),
	}
	p.consensus = &Consensus{Provider: p}
	p.raftStorage = &RaftStorage{raft: p}
	p.meshDB = meshdb.NewFromStorage(p.raftStorage)
	return p
}

// OnObservation registers a callback for when an observation is received.
func (r *Provider) OnObservation(cb ObservationCallback) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observerCbs = append(r.observerCbs, cb)
}

// MeshStorage returns the underlying MeshStorage instance.
func (r *Provider) MeshStorage() storage.MeshStorage {
	return r.raftStorage
}

// MeshDB returns the underlying MeshDB instance.
func (r *Provider) MeshDB() storage.MeshDB {
	return r.meshDB
}

// Consensus returns the underlying Consensus instance.
func (r *Provider) Consensus() storage.Consensus {
	return r.consensus
}

// ListenPort returns the TCP port that the storage provider is listening on.
func (r *Provider) ListenPort() uint16 {
	return r.Options.Transport.AddrPort().Port()
}

// Start starts the raft storage provider.
func (r *Provider) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started.Load() {
		return errors.ErrStarted
	}
	r.log.Debug("Starting raft storage provider")
	storage, err := r.createStorage()
	if err != nil {
		return fmt.Errorf("create storage: %w", err)
	}
	// Set the raft storage instance.
	r.raftStorage.storage = storage
	snapshots, err := r.createSnapshotStorage()
	if err != nil {
		return fmt.Errorf("create snapshot storage: %w", err)
	}
	r.log.Debug("Starting raft instance", slog.String("listen-addr", string(r.Options.Transport.LocalAddr())))
	r.raft, err = raft.NewRaft(
		r.Options.RaftConfig(ctx, string(r.nodeID)),
		fsm.New(ctx, storage, fsm.Options{
			ApplyTimeout: r.Options.ApplyTimeout,
		}),
		&MonotonicLogStore{storage},
		storage,
		snapshots,
		r.Options.Transport,
	)
	if err != nil {
		return fmt.Errorf("new raft: %w", err)
	}
	// Register observers.
	r.observerChan = make(chan raft.Observation, r.Options.ObserverChanBuffer)
	r.observer = raft.NewObserver(r.observerChan, false, func(o *raft.Observation) bool {
		return true
	})
	r.raft.RegisterObserver(r.observer)
	r.observerClose, r.observerDone = r.observe()
	// We're done here.
	r.started.Store(true)
	return nil
}

// Status returns the status of the storage provider.
func (r *Provider) Status() *v1.StorageStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.started.Load() {
		return &v1.StorageStatus{
			IsWritable: false,
			Message:    "raftstorage is closed",
		}
	}
	var status v1.StorageStatus
	config := r.raft.GetConfiguration().Configuration()
	status.IsWritable = r.isVoter()
	leader, err := r.Consensus().GetLeader(context.Background())
	if err != nil {
		r.log.Error("Failed to get leader", "error", err.Error())
	}
	status.ClusterStatus = func() v1.ClusterStatus {
		if leader != nil && leader.GetId() == string(r.nodeID) {
			return v1.ClusterStatus_CLUSTER_LEADER
		}
		if r.isVoter() {
			return v1.ClusterStatus_CLUSTER_VOTER
		}
		if r.isObserver() {
			return v1.ClusterStatus_CLUSTER_OBSERVER
		}
		return v1.ClusterStatus_CLUSTER_NODE
	}()
	status.Message = func() string {
		if r.isVoter() {
			return "current cluster voter"
		}
		if r.isObserver() {
			return "current cluster observer"
		}
		if status.ClusterStatus == v1.ClusterStatus_CLUSTER_LEADER {
			return "current cluster leader"
		}
		return "not a leader, voter, or observer"
	}()
	foundSelf := false
	for _, server := range config.Servers {
		if server.ID == r.nodeID {
			foundSelf = true
		}
		status.Peers = append(status.Peers, &v1.StoragePeer{
			Id:      string(server.ID),
			Address: string(server.Address),
			ClusterStatus: func() v1.ClusterStatus {
				if leader != nil && server.ID == raft.ServerID(leader.GetId()) {
					return v1.ClusterStatus_CLUSTER_LEADER
				}
				switch server.Suffrage {
				case raft.Voter:
					return v1.ClusterStatus_CLUSTER_VOTER
				case raft.Nonvoter:
					return v1.ClusterStatus_CLUSTER_OBSERVER
				default:
					return v1.ClusterStatus_CLUSTER_NODE
				}
			}(),
		})
	}
	if !foundSelf {
		// If we didn't find ourself in the configuration, we are not a member of the cluster,
		// not bootstrapped, or have not been added to the cluster yet. Add ourselves as a regular node.
		status.Peers = append(status.Peers, &v1.StoragePeer{
			Id:            string(r.nodeID),
			Address:       string(r.Options.Transport.LocalAddr()),
			ClusterStatus: v1.ClusterStatus_CLUSTER_NODE,
		})
	}
	return &status
}

// Bootstrap bootstraps the raft storage provider.
func (r *Provider) Bootstrap(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started.Load() {
		return errors.ErrClosed
	}
	port := r.Options.Transport.AddrPort().Port()
	cfg := raft.Configuration{
		Servers: []raft.Server{
			{
				Suffrage: raft.Voter,
				ID:       r.nodeID,
				Address:  raft.ServerAddress(net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port))),
			},
		},
	}
	f := r.raft.BootstrapCluster(cfg)
	err := f.Error()
	if err != nil {
		if err == raft.ErrCantBootstrap {
			return errors.ErrAlreadyBootstrapped
		}
		return fmt.Errorf("bootstrap cluster: %w", err)
	}
	// Wait for the leader to be elected.
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("bootstrap cluster: %w", ctx.Err())
		default:
			addr, id := r.raft.LeaderWithID()
			if addr == "" && id == "" {
				time.Sleep(time.Millisecond * 500)
				continue
			}
			if id != r.nodeID {
				// Something very wrong happened.
				return fmt.Errorf("bootstrap cluster: leader is not us")
			}
			return nil
		}
	}
}

// Close closes the mesh storage and shuts down the raft instance.
func (r *Provider) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started.Load() {
		return nil
	}
	defer func() {
		err := r.raftStorage.Close()
		if err != nil {
			r.log.Error("Error closing storage", "error", err.Error())
		}
	}()
	r.log.Debug("Stopping raft storage provider")
	defer r.log.Debug("Raft storage provider stopped")
	defer r.started.Store(false)
	defer r.raftStorage.Close()
	defer r.Options.Transport.Close()
	// If we were not running in memory, force a snapshot.
	if !r.Options.InMemory {
		r.log.Debug("Taking raft storage snapshot")
		err := r.raft.Snapshot().Error()
		if err != nil {
			// Make this non-fatal for now
			r.log.Error("Failed to take snapshot", slog.String("error", err.Error()))
		}
	}
	r.log.Debug("Shutting down raft node")
	err := r.raft.Shutdown().Error()
	if err != nil {
		return fmt.Errorf("raft shutdown: %w", err)
	}
	return nil
}

// GetRaftConfiguration returns the current raft configuration.
func (r *Provider) GetRaftConfiguration() raft.Configuration {
	return r.raft.GetConfiguration().Configuration()
}

// ApplyRaftLog applies a raft log entry.
func (r *Provider) ApplyRaftLog(ctx context.Context, log *v1.RaftLogEntry) (*v1.RaftApplyResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started.Load() {
		return nil, errors.ErrClosed
	}
	if !r.Consensus().IsLeader() {
		return nil, errors.ErrNotLeader
	}
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	r.log.Debug("Applying log entry",
		slog.String("type", log.Type.String()),
		slog.String("key", string(log.Key)),
		slog.Duration("timeout", timeout),
	)
	data, err := fsm.MarshalLogEntry(log)
	if err != nil {
		return nil, fmt.Errorf("marshal log entry: %w", err)
	}
	f := r.raft.Apply(data, timeout)
	err = f.Error()
	if err != nil {
		return nil, fmt.Errorf("apply: %w", err)
	}
	resp, ok := f.Response().(*v1.RaftApplyResponse)
	if !ok {
		return nil, fmt.Errorf("apply: invalid response type")
	}
	return resp, nil
}

// IsVoter returns true if the Raft node is a voter.
func (r *Provider) isVoter() bool {
	config := r.GetRaftConfiguration()
	for _, server := range config.Servers {
		if server.ID == r.nodeID {
			return server.Suffrage == raft.Voter
		}
	}
	return false
}

// IsObserver returns true if the Raft node is an observer.
func (r *Provider) isObserver() bool {
	config := r.GetRaftConfiguration()
	for _, server := range config.Servers {
		if server.ID == r.nodeID {
			return server.Suffrage == raft.Nonvoter
		}
	}
	return false
}

// createStorage creates the underlying storage.
func (r *Provider) createStorage() (storage.DualStorage, error) {
	if r.Options.InMemory {
		db, err := badgerdb.NewInMemory(badgerdb.Options{
			Debug: func() bool {
				return strings.ToLower(r.Options.LogLevel) == "debug"
			}(),
		})
		if err != nil {
			return nil, fmt.Errorf("create in-memory storage: %w", err)
		}
		return db, nil
	}
	// Make sure the data directory exists
	dataDir := filepath.Join(r.Options.DataDir, r.Options.NodeID.String(), "data")
	// If we are forcing bootstrap, delete the data directory
	if r.Options.ClearDataDir {
		if err := os.RemoveAll(dataDir); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("remove data directory: %w", err)
		}
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("ensure data directory: %w", err)
	}
	db, err := badgerdb.New(badgerdb.Options{
		DiskPath:   dataDir,
		SyncWrites: true,
		Debug: func() bool {
			return strings.ToLower(r.Options.LogLevel) == "debug"
		}(),
	})
	if err != nil {
		return nil, fmt.Errorf("create raft storage: %w", err)
	}
	return db, nil
}

// createSnapshotStorage creates the snapshot storage.
func (r *Provider) createSnapshotStorage() (raft.SnapshotStore, error) {
	if r.Options.InMemory {
		return raft.NewInmemSnapshotStore(), nil
	}
	snapshotStore, err := raft.NewFileSnapshotStoreWithLogger(
		r.Options.DataDir,
		int(r.Options.SnapshotRetention),
		logging.NewHCLogAdapter("", r.Options.LogLevel, r.log.With("component", "snapshotstore")),
	)
	if err != nil {
		return nil, fmt.Errorf("new file snapshot store: %w", err)
	}
	return snapshotStore, nil
}

func (r *Provider) observe() (closeCh, doneCh chan struct{}) {
	closeCh = make(chan struct{})
	doneCh = make(chan struct{})
	go func() {
		defer close(doneCh)
		for {
			select {
			case <-closeCh:
				r.log.Debug("stopping raft observer")
				return
			case ev := <-r.observerChan:
				switch data := ev.Data.(type) {
				case raft.RequestVoteRequest:
					r.log.Debug("RequestVoteRequest", slog.Any("data", data))
				case raft.RaftState:
					r.log.Debug("RaftState", slog.String("data", data.String()))
				case raft.PeerObservation:
					r.log.Debug("PeerObservation", slog.Any("data", data))
				case raft.LeaderObservation:
					r.log.Debug("LeaderObservation", slog.Any("data", data))
				case raft.ResumedHeartbeatObservation:
					r.log.Debug("ResumedHeartbeatObservation", slog.Any("data", data))
				case raft.FailedHeartbeatObservation:
					r.log.Debug("FailedHeartbeatObservation", slog.Any("data", data))
				}
				for _, obs := range r.observerCbs {
					obs(context.Background(), ev)
				}
			}
		}
	}()
	return closeCh, doneCh
}
