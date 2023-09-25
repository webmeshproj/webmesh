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

// Package raft contains Raft consensus for WebMesh.
package raft

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/raft/fsm"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

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

// ObservationCallback is a callback that can be registered for when an observation
// is received.
type ObservationCallback func(ctx context.Context, obs Observation)

// Raft is the interface for Raft consensus and storage.
type Raft interface {
	// Start starts the Raft node.
	Start(ctx context.Context, opts StartOptions) error
	// ID returns the node ID.
	ID() string
	// OnObservation registers a callback for when an observation is received.
	OnObservation(cb ObservationCallback)
	// Bootstrap attempts to bootstrap the Raft cluster. If the cluster is already
	// bootstrapped, ErrAlreadyBootstrapped is returned.
	Bootstrap(ctx context.Context) error
	// Storage returns the storage. This is only valid after Start is called.
	Storage() storage.MeshStorage
	// Configuration returns the current raft configuration.
	Configuration() (raft.Configuration, error)
	// LastIndex returns the last index sent to the Raft instance.
	LastIndex() uint64
	// LastAppliedIndex returns the last applied index.
	LastAppliedIndex() uint64
	// ListenPort returns the listen port.
	ListenPort() uint16
	// LeaderID returns the leader ID.
	LeaderID() (string, error)
	// IsLeader returns true if the Raft node is the leader.
	IsLeader() bool
	// IsVoter returns true if the Raft node is a voter.
	IsVoter() bool
	// IsObserver returns true if the Raft node is an observer.
	IsObserver() bool
	// IsMember is a convenience method that returns true if the Raft node is a voter or observer.
	IsMember() bool
	// AddNonVoter adds a non-voting node to the cluster with timeout enforced by the context.
	AddNonVoter(ctx context.Context, id string, addr string) error
	// AddVoter adds a voting node to the cluster with timeout enforced by the context.
	AddVoter(ctx context.Context, id string, addr string) error
	// DemoteVoter demotes a voting node to a non-voting node with timeout enforced by the context.
	DemoteVoter(ctx context.Context, id string) error
	// RemoveServer removes a peer from the cluster with timeout enforced by the context.
	RemoveServer(ctx context.Context, id string, wait bool) error
	// Apply applies a raft log entry.
	Apply(ctx context.Context, log *v1.RaftLogEntry) (*v1.RaftApplyResponse, error)
	// Snapshot requests a raft snapshot. It returns a reader containing the contents
	// and metadata about the snapshot.
	Snapshot() (*raft.SnapshotMeta, io.ReadCloser, error)
	// Barrier issues a barrier request to the cluster. This is a no-op if the node is not the leader.
	Barrier(ctx context.Context, timeout time.Duration) (took time.Duration, err error)
	// Stop stops the Raft node.
	Stop(ctx context.Context) error
}

// New returns a new Raft node.
func New(ctx context.Context, opts Options) Raft {
	return newRaftNode(ctx, opts)
}

// raftNode is a Raft node. It implements the Raft interface.
type raftNode struct {
	started                     atomic.Bool
	fsm                         *fsm.RaftFSM
	opts                        Options
	nodeID                      raft.ServerID
	raft                        *raft.Raft
	raftTransport               transport.RaftTransport
	raftDB                      *raftStorage
	observer                    *raft.Observer
	observerChan                chan raft.Observation
	observerClose, observerDone chan struct{}
	observationcbs              []ObservationCallback
	log                         *slog.Logger
	cbmu                        sync.Mutex
	mu                          sync.Mutex
}

// newRaftNode returns a new Raft node.
func newRaftNode(ctx context.Context, opts Options) *raftNode {
	log := context.LoggerFrom(ctx).With(slog.String("component", "raft"))
	if opts.InMemory {
		log = log.With(slog.String("storage", ":memory:"))
	} else {
		log = log.With(slog.String("storage", opts.DataDir))
	}
	return &raftNode{
		opts:   opts,
		nodeID: raft.ServerID(opts.NodeID),
		log:    log,
	}
}

// ID returns the node ID.
func (r *raftNode) ID() string {
	return string(r.nodeID)
}

// OnObservation registers a callback for when an observation is received.
func (r *raftNode) OnObservation(cb ObservationCallback) {
	r.cbmu.Lock()
	defer r.cbmu.Unlock()
	r.observationcbs = append(r.observationcbs, cb)
}

// StartOptons are options for starting a Raft node.
type StartOptions struct {
	// Transport is the Raft transport.
	Transport transport.RaftTransport
	// MeshStorage is the mesh storage.
	MeshStorage storage.MeshStorage
	// RaftStorage is the Raft storage.
	RaftStorage storage.RaftStorage
}

// Start starts the Raft node.
func (r *raftNode) Start(ctx context.Context, opts StartOptions) error {
	if r.started.Load() {
		return ErrStarted
	}
	r.mu.Lock()
	r.raftTransport = opts.Transport
	r.raftDB = &raftStorage{MeshStorage: opts.MeshStorage, raft: r}
	// Create the snapshot stores
	var snapshotStore raft.SnapshotStore
	if r.opts.InMemory {
		snapshotStore = raft.NewInmemSnapshotStore()
	} else {
		var err error
		snapshotStore, err = raft.NewFileSnapshotStoreWithLogger(
			r.opts.DataDir,
			int(r.opts.SnapshotRetention),
			logging.NewHCLogAdapter("", r.opts.LogLevel, r.log.With("component", "snapshotstore")),
		)
		if err != nil {
			r.mu.Unlock()
			return fmt.Errorf("new file snapshot store: %w", err)
		}
	}
	// Create the raft instance.
	r.log.Info("starting raft instance", slog.String("listen-addr", string(r.raftTransport.LocalAddr())))
	// We unlock here so raft can call back into the Apply/RestoreSnapshot methods if needed.
	r.mu.Unlock()
	var err error
	r.fsm = fsm.New(ctx, opts.MeshStorage, fsm.Options{
		ApplyTimeout: r.opts.ApplyTimeout,
	})
	r.raft, err = raft.NewRaft(
		r.opts.RaftConfig(ctx, string(r.nodeID)),
		r.fsm,
		&MonotonicLogStore{opts.RaftStorage},
		opts.RaftStorage,
		snapshotStore,
		r.raftTransport)
	if err != nil {
		return fmt.Errorf("new raft: %w", err)
	}
	// Register observers.
	r.observerChan = make(chan raft.Observation, r.opts.ObserverChanBuffer)
	r.observer = raft.NewObserver(r.observerChan, false, func(o *raft.Observation) bool {
		return true
	})
	r.raft.RegisterObserver(r.observer)
	r.observerClose, r.observerDone = r.observe()
	// We're done here.
	r.started.Store(true)
	return nil
}

// Bootstrap attempts to bootstrap the Raft cluster.
func (r *raftNode) Bootstrap(ctx context.Context) error {
	r.mu.Lock()
	if !r.started.Load() {
		r.mu.Unlock()
		return ErrClosed
	}
	port := r.raftTransport.AddrPort().Port()
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
		r.mu.Unlock()
		if err == raft.ErrCantBootstrap {
			return ErrAlreadyBootstrapped
		}
		return fmt.Errorf("bootstrap cluster: %w", err)
	}
	// Wait for the leader to be elected.
	for {
		select {
		case <-ctx.Done():
			r.mu.Unlock()
			return fmt.Errorf("bootstrap cluster: %w", ctx.Err())
		default:
			addr, id := r.raft.LeaderWithID()
			if addr == "" && id == "" {
				time.Sleep(time.Millisecond * 500)
				continue
			}
			r.mu.Unlock()
			if id != r.nodeID {
				// Something very wrong happened.
				return fmt.Errorf("bootstrap cluster: leader is not us")
			}
			return nil
		}
	}
}

// Raft returns the Raft instance.
func (r *raftNode) Raft() *raft.Raft {
	return r.raft
}

// Configuration returns the current raft configuration.
func (r *raftNode) Configuration() (raft.Configuration, error) {
	if r.raft == nil {
		return raft.Configuration{}, ErrClosed
	}
	return r.raft.GetConfiguration().Configuration(), nil
}

// ListenPort returns the listen port.
func (r *raftNode) ListenPort() uint16 {
	return r.raftTransport.AddrPort().Port()
}

// LastIndex returns the last index sent to the Raft instance.
func (r *raftNode) LastIndex() uint64 {
	return r.raft.LastIndex()
}

// LastAppliedIndex returns the last applied index.
func (r *raftNode) LastAppliedIndex() uint64 {
	return r.fsm.LastAppliedIndex()
}

func (r *raftNode) LeaderID() (string, error) {
	_, id := r.raft.LeaderWithID()
	if id == "" {
		return "", ErrNoLeader
	}
	return string(id), nil
}

// IsLeader returns true if the Raft node is the leader.
func (r *raftNode) IsLeader() bool {
	return r.raft.State() == raft.Leader
}

// IsMember is a convenience method that returns true if the Raft node is a voter or observer.
func (r *raftNode) IsMember() bool {
	// Non raft-members should be using the passthrough transport.
	return true
}

// IsVoter returns true if the Raft node is a voter.
func (r *raftNode) IsVoter() bool {
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
func (r *raftNode) IsObserver() bool {
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

// Storage returns the storage.
func (r *raftNode) Storage() storage.MeshStorage {
	return r.raftDB
}

// Apply applies a raft log entry.
func (r *raftNode) Apply(ctx context.Context, log *v1.RaftLogEntry) (*v1.RaftApplyResponse, error) {
	if !r.IsLeader() {
		return nil, ErrNotLeader
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

// Snapshot requests a raft snapshot. It returns a reader containing the contents
// and metadata about the snapshot.
func (r *raftNode) Snapshot() (*raft.SnapshotMeta, io.ReadCloser, error) {
	f := r.raft.Snapshot()
	if err := f.Error(); err != nil {
		return nil, nil, err
	}
	return f.Open()
}

// Barrier issues a barrier request to the cluster. If the node is not leader
// then ErrNotLeader is returned.
func (r *raftNode) Barrier(ctx context.Context, timeout time.Duration) (took time.Duration, err error) {
	if !r.IsLeader() {
		return 0, ErrNotLeader
	}
	start := time.Now()
	log := context.LoggerFrom(ctx)
	log.Debug("Sending barrier to raft cluster", slog.Duration("timeout", timeout))
	err = r.Raft().Barrier(timeout).Error()
	took = time.Since(start)
	if err == nil {
		log.Debug("Barrier request succeeded", slog.Duration("took", took))
		return took, nil
	}
	log.Error("Barrier request failed", slog.String("error", err.Error()), slog.Duration("took", took))
	return took, err
}

// Stop stops the Raft node.
func (r *raftNode) Stop(ctx context.Context) error {
	if !r.started.Load() {
		return ErrClosed
	}
	r.log.Debug("stopping raft node")
	defer r.log.Debug("raft node stopped")
	defer r.started.Store(false)
	defer r.raftTransport.Close()
	// If we were not running in memory, force a snapshot.
	if !r.opts.InMemory {
		r.log.Debug("taking raft storage snapshot")
		err := r.raft.Snapshot().Error()
		if err != nil {
			// Make this non-fatal for now
			r.log.Error("failed to take snapshot", slog.String("error", err.Error()))
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.raft.State() == raft.Leader {
		r.log.Debug("raft node is current leader, stepping down")
		if err := r.raft.LeadershipTransfer().Error(); err != nil && err != ErrNotLeader {
			r.log.Error("failed to transfer leadership", slog.String("error", err.Error()))
		}
	}
	// Shut down the storage when we're done.
	defer func() {
		err := r.raftDB.Close()
		if err != nil {
			r.log.Error("failed to close raft storage", slog.String("error", err.Error()))
		}
	}()
	r.log.Debug("shutting down raft node")
	err := r.raft.Shutdown().Error()
	if err != nil {
		return fmt.Errorf("raft shutdown: %w", err)
	}
	return nil
}
