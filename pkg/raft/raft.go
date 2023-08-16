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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb/snapshots"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/util"
)

var (
	// ErrStarted is returned when the Raft node is already started.
	ErrStarted = errors.New("raft node already started")
	// ErrClosed is returned when the Raft node is already closed.
	ErrClosed = errors.New("raft node is closed")
	// ErrAlreadyBootstrapped is returned when the Raft node is already bootstrapped.
	ErrAlreadyBootstrapped = raft.ErrCantBootstrap
	// ErrNotLeader is returned when the Raft node is not the leader.
	ErrNotLeader = raft.ErrNotLeader
	// ErrNotVoter is returned when the Raft node is not a voter.
	ErrNotVoter = raft.ErrNotVoter
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

// LeaderDialer is the interface for dialing the leader.
type LeaderDialer interface {
	DialLeader(ctx context.Context) (*grpc.ClientConn, error)
}

// LeaderDialerFunc is the function signature for dialing the leader.
// It is supplied by the mesh during startup. It can be used as an
// alternative to the LeaderDialer interface.
type LeaderDialerFunc func(ctx context.Context) (*grpc.ClientConn, error)

func (f LeaderDialerFunc) DialLeader(ctx context.Context) (*grpc.ClientConn, error) {
	return f(ctx)
}

// NodeDialer is an interface for dialing an arbitrary node. The node ID
// is optional and if empty, implementations can choose the node to dial.
type NodeDialer interface {
	Dial(ctx context.Context, id string) (*grpc.ClientConn, error)
}

// NodeDialerFunc is the function signature for dialing an arbitrary node.
// It is supplied by the mesh during startup. It can be used as an
// alternative to the NodeDialer interface.
type NodeDialerFunc func(ctx context.Context, id string) (*grpc.ClientConn, error)

func (f NodeDialerFunc) Dial(ctx context.Context, id string) (*grpc.ClientConn, error) {
	return f(ctx, id)
}

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

// Raft is the interface for Raft consensus and storage.
type Raft interface {
	// Start starts the Raft node.
	Start(ctx context.Context, opts *StartOptions) error
	// Bootstrap attempts to bootstrap the Raft cluster. If the cluster is already
	// bootstrapped, ErrAlreadyBootstrapped is returned. If the cluster is not
	// bootstrapped and bootstrapping succeeds, the optional callback is called
	// with isLeader flag set to true if the node is the leader, and false otherwise.
	// Any error returned by the callback is returned by Bootstrap.
	Bootstrap(ctx context.Context, opts *BootstrapOptions) error
	// Storage returns the storage. This is only valid after Start is called.
	Storage() storage.Storage
	// Configuration returns the current raft configuration.
	Configuration() (raft.Configuration, error)
	// LastIndex returns the last index sent to the Raft instance.
	LastIndex() uint64
	// LastAppliedIndex returns the last applied index.
	LastAppliedIndex() uint64
	// ListenPort returns the listen port.
	ListenPort() int
	// LeaderID returns the leader ID.
	LeaderID() (string, error)
	// IsLeader returns true if the Raft node is the leader.
	IsLeader() bool
	// IsVoter returns true if the Raft node is a voter.
	IsVoter() bool
	// IsObserver returns true if the Raft node is an observer.
	IsObserver() bool
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

// StartOptons are options for starting a Raft node.
type StartOptions struct {
	// NodeID is the node ID.
	NodeID string
}

// BootstrapOptions are options for bootstrapping a Raft node.
type BootstrapOptions struct {
	// AdvertiseAddress is the address to advertise to the other
	// bootstrap nodes. Defaults to localhost:listen_port if empty.
	AdvertiseAddress string
	// Servers are the Raft servers to bootstrap with.
	// Keys are the node IDs, and values are the Raft addresses.
	Servers map[string]string
	// OnBootstrapped is called when the cluster is bootstrapped.
	OnBootstrapped func(isLeader bool) error
}

// New returns a new Raft node.
func New(opts *Options, dialer LeaderDialer) Raft {
	return newRaftNode(opts, dialer)
}

// raftNode is a Raft node. It implements the Raft interface.
type raftNode struct {
	opts                        *Options
	nodeID                      raft.ServerID
	raft                        *raft.Raft
	started                     atomic.Bool
	lastAppliedIndex            atomic.Uint64
	currentTerm                 atomic.Uint64
	listenPort                  int
	raftTransport               *raft.NetworkTransport
	raftSnapshots               raft.SnapshotStore
	logDB                       LogStoreCloser
	stableDB                    StableStoreCloser
	dataDB                      storage.Storage
	raftDB                      *raftStorage
	snapshotter                 snapshots.Snapshotter
	observer                    *raft.Observer
	observerChan                chan raft.Observation
	observerClose, observerDone chan struct{}
	leaderDialer                LeaderDialer
	log                         *slog.Logger
	mu                          sync.Mutex
}

// newRaftNode returns a new Raft node.
func newRaftNode(opts *Options, dialer LeaderDialer) *raftNode {
	log := slog.Default().With(slog.String("component", "raft"))
	if opts.InMemory {
		log = log.With(slog.String("storage", "memory"))
	} else {
		log = log.With(slog.String("storage", opts.DataDir))
	}
	return &raftNode{opts: opts, log: log, leaderDialer: dialer}
}

// Start starts the Raft node.
func (r *raftNode) Start(ctx context.Context, opts *StartOptions) error {
	if r.started.Load() {
		return ErrStarted
	}
	r.mu.Lock()
	r.nodeID = raft.ServerID(opts.NodeID)
	// Ensure the data directories exist if not in-memory
	if !r.opts.InMemory {
		for _, dir := range []string{r.opts.StorePath(), r.opts.DataStoragePath()} {
			err := os.MkdirAll(dir, 0755)
			if err != nil {
				r.mu.Unlock()
				return fmt.Errorf("raft mkdir %q: %w", dir, err)
			}
		}
	}
	// Create the raft network transport
	r.log.Debug("creating raft network transport")
	sl, err := NewStreamLayer(r.opts.ListenAddress)
	if err != nil {
		r.mu.Unlock()
		return fmt.Errorf("new raft stream layer: %w", err)
	}
	r.listenPort = sl.ListenPort()
	r.raftTransport = raft.NewNetworkTransport(sl,
		r.opts.ConnectionPoolCount,
		r.opts.ConnectionTimeout,
		&logWriter{log: r.log},
	)
	// Create the stores
	r.log.Debug("creating raft stores")
	err = r.createDataStores(ctx)
	if err != nil {
		r.mu.Unlock()
		defer r.raftTransport.Close()
		return fmt.Errorf("create data stores: %w", err)
	}
	r.raftDB = &raftStorage{r.dataDB, r}
	r.snapshotter = snapshots.New(r.dataDB)
	handleErr := func(cause error) error {
		defer r.raftTransport.Close()
		defer r.closeDataStores(ctx)
		return cause
	}
	// Create the raft instance.
	r.log.Info("starting raft instance", slog.String("listen-addr", string(r.raftTransport.LocalAddr())))
	// We unlock here so raft can call back into the Apply/RestoreSnapshot methods if needed.
	r.mu.Unlock()
	r.raft, err = raft.NewRaft(
		r.opts.RaftConfig(opts.NodeID),
		&raftNodeFSM{r},
		&MonotonicLogStore{r.logDB},
		r.stableDB,
		r.raftSnapshots,
		r.raftTransport)
	if err != nil {
		return handleErr(fmt.Errorf("new raft: %w", err))
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
func (r *raftNode) Bootstrap(ctx context.Context, opts *BootstrapOptions) error {
	r.mu.Lock()
	if !r.started.Load() {
		r.mu.Unlock()
		return ErrClosed
	}
	if opts.AdvertiseAddress == "" {
		opts.AdvertiseAddress = fmt.Sprintf("localhost:%d", r.listenPort)
	}
	addr, err := util.ResolveTCPAddr(ctx, opts.AdvertiseAddress, 15)
	if err != nil {
		r.mu.Unlock()
		return fmt.Errorf("resolve advertise address: %w", err)
	}
	cfg := raft.Configuration{
		Servers: []raft.Server{
			{
				Suffrage: raft.Voter,
				ID:       r.nodeID,
				Address:  raft.ServerAddress(addr.String()),
			},
		},
	}
	if len(opts.Servers) > 0 {
		for nodeID, listenAddres := range opts.Servers {
			if nodeID == string(r.nodeID) {
				continue
			}
			addr, err := util.ResolveTCPAddr(ctx, listenAddres, 15)
			if err != nil {
				r.mu.Unlock()
				return fmt.Errorf("resolve server address: %w", err)
			}
			cfg.Servers = append(cfg.Servers, raft.Server{
				Suffrage: raft.Voter,
				ID:       raft.ServerID(nodeID),
				Address:  raft.ServerAddress(addr.String()),
			})
		}
	}
	f := r.raft.BootstrapCluster(cfg)
	err = f.Error()
	if err != nil {
		defer r.mu.Unlock()
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
			// We need to unlock before return as the OnBootstrapped
			// callback will want to write to storage.
			r.mu.Unlock()
			if opts.OnBootstrapped == nil {
				return nil
			}
			isLeader := id == r.nodeID
			return opts.OnBootstrapped(isLeader)
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
func (r *raftNode) ListenPort() int {
	return r.listenPort
}

// LastIndex returns the last index sent to the Raft instance.
func (r *raftNode) LastIndex() uint64 {
	return r.raft.LastIndex()
}

// LastAppliedIndex returns the last applied index.
func (r *raftNode) LastAppliedIndex() uint64 {
	return r.lastAppliedIndex.Load()
}

func (r *raftNode) LeaderID() (string, error) {
	_, id := r.raft.LeaderWithID()
	if id == "" {
		return "", ErrNotLeader
	}
	return string(id), nil
}

// IsLeader returns true if the Raft node is the leader.
func (r *raftNode) IsLeader() bool {
	return r.raft.State() == raft.Leader
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
func (r *raftNode) Storage() storage.Storage {
	return r.raftDB
}

// Apply applies a raft log entry.
func (r *raftNode) Apply(ctx context.Context, log *v1.RaftLogEntry) (*v1.RaftApplyResponse, error) {
	var timeout time.Duration
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	data, err := MarshalLogEntry(log)
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
	defer r.closeDataStores(ctx)
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
	r.log.Debug("shutting down raft node")
	err := r.raft.Shutdown().Error()
	if err != nil {
		return fmt.Errorf("raft shutdown: %w", err)
	}
	return nil
}
