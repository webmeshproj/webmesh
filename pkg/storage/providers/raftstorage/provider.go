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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/backends/badgerdb"
	"github.com/webmeshproj/webmesh/pkg/storage/providers/raftstorage/fsm"
)

// Ensure we satisfy the provider interface.
var _ storage.Provider = &Provider{}
var _ storage.Consensus = &Consensus{}
var _ storage.MeshStorage = &RaftStorage{}

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
	storage                     *RaftStorage
	fsm                         *fsm.RaftFSM
	observer                    *raft.Observer
	observerChan                chan raft.Observation
	observerClose, observerDone chan struct{}
	observerCbs                 []ObservationCallback
	log                         *slog.Logger
	mu                          sync.RWMutex
}

// NewProvider returns a new RaftStorageProvider.
func NewProvider(opts Options) *Provider {
	return &Provider{
		Options: opts,
		nodeID:  raft.ServerID(opts.NodeID),
		log:     logging.NewLogger(opts.LogLevel).With("component", "raftstorage"),
	}
}

// OnObservation registers a callback for when an observation is received.
func (r *Provider) OnObservation(cb ObservationCallback) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.observerCbs = append(r.observerCbs, cb)
}

// MeshStorage returns the underlying MeshStorage instance.
func (r *Provider) MeshStorage() storage.MeshStorage {
	return r.storage
}

// Consensus returns the underlying Consensus instance.
func (r *Provider) Consensus() storage.Consensus {
	return &Consensus{Provider: r}
}

// ListenPort returns the TCP port that the storage provider is listening on.
func (r *Provider) ListenPort() uint16 {
	return r.Options.Transport.AddrPort().Port()
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
	status.IsWritable = r.IsVoter()
	leader, err := r.Consensus().GetLeader(context.Background())
	if err != nil {
		r.log.Error("Failed to get leader", "error", err.Error())
	}
	status.ClusterStatus = func() v1.ClusterStatus {
		if leader != nil && leader.GetId() == string(r.nodeID) {
			return v1.ClusterStatus_CLUSTER_LEADER
		}
		if r.IsVoter() {
			return v1.ClusterStatus_CLUSTER_VOTER
		}
		if r.IsObserver() {
			return v1.ClusterStatus_CLUSTER_OBSERVER
		}
		return v1.ClusterStatus_CLUSTER_NODE
	}()
	status.Message = func() string {
		if r.IsVoter() {
			return "current cluster voter"
		}
		if r.IsObserver() {
			return "current cluster observer"
		}
		if status.ClusterStatus == v1.ClusterStatus_CLUSTER_LEADER {
			return "current cluster leader"
		}
		return "not a leader, voter, or observer"
	}()
	for _, server := range config.Servers {
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
	return &status
}

// Start starts the raft storage provider.
func (r *Provider) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started.Load() {
		return storage.ErrStarted
	}
	log := r.log
	log.Debug("Starting raft storage provider")
	storage, err := r.createStorage()
	if err != nil {
		return fmt.Errorf("create storage: %w", err)
	}
	r.storage = &RaftStorage{MeshStorage: storage, raft: r}
	snapshots, err := r.createSnapshotStorage()
	if err != nil {
		return fmt.Errorf("create snapshot storage: %w", err)
	}
	log.Debug("Starting raft instance", slog.String("listen-addr", string(r.Options.Transport.LocalAddr())))
	r.fsm = fsm.New(ctx, storage, fsm.Options{
		ApplyTimeout: r.Options.ApplyTimeout,
	})
	r.raft, err = raft.NewRaft(
		r.Options.RaftConfig(ctx, string(r.nodeID)),
		r.fsm,
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

// createStorage creates the underlying storage.
func (r *Provider) createStorage() (storage.DualStorage, error) {
	if r.Options.InMemory {
		db, err := badgerdb.New(badgerdb.Options{InMemory: true})
		if err != nil {
			return nil, fmt.Errorf("create in-memory storage: %w", err)
		}
		return db, nil
	}
	// Make sure the data directory exists
	dataDir := filepath.Join(r.Options.DataDir, "data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	// If we are forcing bootstrap, delete the data directory
	if r.Options.ClearDataDir {
		if err := os.RemoveAll(dataDir); err != nil {
			return nil, fmt.Errorf("remove data directory: %w", err)
		}
	}
	db, err := badgerdb.New(badgerdb.Options{
		DiskPath: dataDir,
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

// Bootstrap bootstraps the raft storage provider.
func (r *Provider) Bootstrap(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started.Load() {
		return storage.ErrClosed
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
			return storage.ErrAlreadyBootstrapped
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
		err := r.storage.Close()
		if err != nil {
			r.log.Error("Error closing storage", "error", err.Error())
		}
	}()
	r.log.Debug("Stopping raft storage provider")
	defer r.log.Debug("Raft storage provider stopped")
	defer r.started.Store(false)
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
	// If we were the leader, step down.
	if r.raft.State() == raft.Leader {
		r.log.Debug("Raft node is current leader, stepping down")
		if err := r.raft.LeadershipTransfer().Error(); err != nil && !errors.Is(err, raft.ErrNotLeader) {
			r.log.Warn("Failed to transfer leadership", slog.String("error", err.Error()))
		}
	}
	r.log.Debug("Shutting down raft node")
	err := r.raft.Shutdown().Error()
	if err != nil {
		return fmt.Errorf("raft shutdown: %w", err)
	}
	return nil
}

// IsVoter returns true if the Raft node is a voter.
func (r *Provider) IsVoter() bool {
	config, err := r.Configuration()
	if err != nil {
		return false
	}
	for _, server := range config.Servers {
		if server.ID == r.nodeID {
			return server.Suffrage == raft.Voter
		}
	}
	return false
}

// IsObserver returns true if the Raft node is an observer.
func (r *Provider) IsObserver() bool {
	config, err := r.Configuration()
	if err != nil {
		return false
	}
	for _, server := range config.Servers {
		if server.ID == r.nodeID {
			return server.Suffrage == raft.Nonvoter
		}
	}
	return false
}

// Configuration returns the current raft configuration.
func (r *Provider) Configuration() (raft.Configuration, error) {
	if r.raft == nil {
		return raft.Configuration{}, storage.ErrClosed
	}
	return r.raft.GetConfiguration().Configuration(), nil
}

// Apply applies a raft log entry.
func (r *Provider) Apply(ctx context.Context, log *v1.RaftLogEntry) (*v1.RaftApplyResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started.Load() {
		return nil, storage.ErrClosed
	}
	if !r.Consensus().IsLeader() {
		return nil, storage.ErrNotLeader
	}
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	r.log.Debug("applying log entry", slog.String("type", log.Type.String()), slog.String("key", log.Key), slog.Duration("timeout", timeout))
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

// RaftConsensus is the Raft consensus implementation.
type Consensus struct {
	*Provider
}

// IsLeader returns true if the Raft node is the leader.
func (r *Consensus) IsLeader() bool {
	return r.raft.State() == raft.Leader
}

// GetLeader returns the leader of the cluster.
func (r *Consensus) GetLeader(ctx context.Context) (*v1.StoragePeer, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.started.Load() {
		return nil, storage.ErrClosed
	}
	if r.IsLeader() {
		// Fast path for leader.
		return &v1.StoragePeer{
			Id:            string(r.nodeID),
			Address:       string(r.Options.Transport.LocalAddr()),
			ClusterStatus: v1.ClusterStatus_CLUSTER_LEADER,
		}, nil
	}
	// Slow path for non-leaders.
	leaderAddr, leaderID := r.raft.LeaderWithID()
	if leaderAddr == "" && leaderID == "" {
		return nil, storage.ErrNoLeader
	}
	return &v1.StoragePeer{
		Id:            string(leaderID),
		Address:       string(leaderAddr),
		ClusterStatus: v1.ClusterStatus_CLUSTER_LEADER,
	}, nil
}

// IsMember returns true if the Raft node is a member of the cluster.
func (r *Consensus) IsMember() bool {
	// We fast path this to avoid the lock and avoid race conditions
	// if voter propagation is slow.
	// Non raft-members use the passthrough storage.
	return true
}

// AddVoter adds a voter to the consensus group.
func (r *Consensus) AddVoter(ctx context.Context, peer *v1.StoragePeer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started.Load() {
		return storage.ErrClosed
	}
	if !r.IsLeader() {
		return storage.ErrNotLeader
	}
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	f := r.raft.AddVoter(raft.ServerID(peer.GetId()), raft.ServerAddress(peer.GetAddress()), 0, timeout)
	err := f.Error()
	if err != nil && errors.Is(err, raft.ErrNotLeader) {
		return storage.ErrNotLeader
	}
	return err
}

// AddObserver adds an observer to the consensus group.
func (r *Consensus) AddObserver(ctx context.Context, peer *v1.StoragePeer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started.Load() {
		return storage.ErrClosed
	}
	if !r.IsLeader() {
		return storage.ErrNotLeader
	}
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	f := r.raft.AddNonvoter(raft.ServerID(peer.GetId()), raft.ServerAddress(peer.GetAddress()), 0, timeout)
	err := f.Error()
	if err != nil && errors.Is(err, raft.ErrNotLeader) {
		return storage.ErrNotLeader
	}
	return err
}

// DemoteVoter demotes a voter to an observer.
func (r *Consensus) DemoteVoter(ctx context.Context, peer *v1.StoragePeer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started.Load() {
		return storage.ErrClosed
	}
	if !r.IsLeader() {
		return storage.ErrNotLeader
	}
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	f := r.raft.DemoteVoter(raft.ServerID(peer.GetId()), 0, timeout)
	err := f.Error()
	if err != nil && errors.Is(err, raft.ErrNotLeader) {
		return storage.ErrNotLeader
	}
	return err
}

// RemovePeer removes a peer from the consensus group.
func (r *Consensus) RemovePeer(ctx context.Context, peer *v1.StoragePeer, wait bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started.Load() {
		return storage.ErrClosed
	}
	if !r.IsLeader() {
		return storage.ErrNotLeader
	}
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	f := r.raft.RemoveServer(raft.ServerID(peer.GetId()), 0, timeout)
	if !wait {
		return nil
	}
	err := f.Error()
	if err != nil && errors.Is(err, raft.ErrNotLeader) {
		return storage.ErrNotLeader
	}
	return err
}
