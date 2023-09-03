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

package config

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/net/transport/tcp"
	"github.com/webmeshproj/webmesh/pkg/raft"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/memory"
	"github.com/webmeshproj/webmesh/pkg/storage/nutsdb"
)

// RaftOptions are options for the raft backend.
type RaftOptions struct {
	// ListenAddress is the address to listen on.
	ListenAddress string `koanf:"listen-address,omitempty"`
	// DataDir is the directory to store data in.
	DataDir string `koanf:"data-dir,omitempty"`
	// InMemory is if the store should be in memory. This should only be used for testing and ephemeral nodes.
	InMemory bool `koanf:"in-memory,omitempty"`
	// ConnectionPoolCount is the number of connections to pool. If 0, no connection pooling is used.
	ConnectionPoolCount int `koanf:"connection-pool-count,omitempty"`
	// ConnectionTimeout is the timeout for connections.
	ConnectionTimeout time.Duration `koanf:"connection-timeout,omitempty"`
	// HeartbeatTimeout is the timeout for heartbeats.
	HeartbeatTimeout time.Duration `koanf:"heartbeat-timeout,omitempty"`
	// ElectionTimeout is the timeout for elections.
	ElectionTimeout time.Duration `koanf:"election-timeout,omitempty"`
	// ApplyTimeout is the timeout for applying.
	ApplyTimeout time.Duration `koanf:"apply-timeout,omitempty"`
	// CommitTimeout is the timeout for committing.
	CommitTimeout time.Duration `koanf:"commit-timeout,omitempty"`
	// MaxAppendEntries is the maximum number of append entries.
	MaxAppendEntries int `koanf:"max-append-entries,omitempty"`
	// LeaderLeaseTimeout is the timeout for leader leases.
	LeaderLeaseTimeout time.Duration `koanf:"leader-lease-timeout,omitempty"`
	// SnapshotInterval is the interval to take snapshots.
	SnapshotInterval time.Duration `koanf:"snapshot-interval,omitempty"`
	// SnapshotThreshold is the threshold to take snapshots.
	SnapshotThreshold uint64 `koanf:"snapshot-threshold,omitempty"`
	// SnapshotRetention is the number of snapshots to retain.
	SnapshotRetention uint64 `koanf:"snapshot-retention,omitempty"`
	// ObserverChanBuffer is the buffer size for the observer channel.
	ObserverChanBuffer int `koanf:"observer-chan-buffer,omitempty"`
	// RequestVote is true if the node should request a vote in raft elections.
	RequestVote bool `koanf:"request-vote,omitempty"`
	// RequestObserver is true if the node should be a raft observer.
	RequestObserver bool `koanf:"request-observer,omitempty"`
	// PreferIPv6 is the prefer IPv6 flag.
	PreferIPv6 bool `koanf:"prefer-ipv6,omitempty"`
	// HeartbeatPurgeThreshold is the threshold of failed heartbeats before purging a peer.
	HeartbeatPurgeThreshold int `koanf:"heartbeat-purge-threshold,omitempty"`
	// LogLevel is the log level for the raft backend.
	LogLevel string `koanf:"log-level,omitempty"`
}

// NewRaftOptions returns a new RaftOptions with the default values.
func NewRaftOptions() RaftOptions {
	return RaftOptions{
		ListenAddress:           raft.DefaultListenAddress,
		DataDir:                 raft.DefaultDataDir,
		InMemory:                false,
		ConnectionPoolCount:     0,
		ConnectionTimeout:       3 * time.Second,
		HeartbeatTimeout:        time.Second * 2,
		ElectionTimeout:         time.Second * 2,
		ApplyTimeout:            10 * time.Second,
		CommitTimeout:           10 * time.Second,
		MaxAppendEntries:        64,
		LeaderLeaseTimeout:      time.Second * 2,
		SnapshotInterval:        30 * time.Second,
		SnapshotThreshold:       8192,
		SnapshotRetention:       2,
		ObserverChanBuffer:      100,
		RequestVote:             false,
		RequestObserver:         false,
		PreferIPv6:              false,
		HeartbeatPurgeThreshold: 25,
		LogLevel:                "info",
	}
}

// BindFlags binds the flags.
func (o *RaftOptions) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.StringVar(&o.ListenAddress, prefix+"raft.listen-address", raft.DefaultListenAddress, "Raft listen address.")
	fs.StringVar(&o.DataDir, prefix+"raft.data-dir", raft.DefaultDataDir, "Raft data directory.")
	fs.BoolVar(&o.InMemory, prefix+"raft.in-memory", false, "Run raft with in-memory storage.")
	fs.IntVar(&o.ConnectionPoolCount, prefix+"raft.connection-pool-count", 0, "Raft connection pool count.")
	fs.DurationVar(&o.ConnectionTimeout, prefix+"raft.connection-timeout", time.Second*3, "Raft connection timeout.")
	fs.DurationVar(&o.HeartbeatTimeout, prefix+"raft.heartbeat-timeout", time.Second*2, "Raft heartbeat timeout.")
	fs.DurationVar(&o.ElectionTimeout, prefix+"raft.election-timeout", time.Second*2, "Raft election timeout.")
	fs.DurationVar(&o.ApplyTimeout, prefix+"raft.apply-timeout", 10*time.Second, "Raft apply timeout.")
	fs.DurationVar(&o.CommitTimeout, prefix+"raft.commit-timeout", 10*time.Second, "Raft commit timeout.")
	fs.IntVar(&o.MaxAppendEntries, prefix+"raft.max-append-entries", 64, "Raft max append entries.")
	fs.DurationVar(&o.LeaderLeaseTimeout, prefix+"raft.leader-lease-timeout", time.Second*2, "Raft leader lease timeout.")
	fs.DurationVar(&o.SnapshotInterval, prefix+"raft.snapshot-interval", 30*time.Second, "Raft snapshot interval.")
	fs.Uint64Var(&o.SnapshotThreshold, prefix+"raft.snapshot-threshold", 8192, "Raft snapshot threshold.")
	fs.Uint64Var(&o.SnapshotRetention, prefix+"raft.snapshot-retention", 2, "Raft snapshot retention.")
	fs.IntVar(&o.ObserverChanBuffer, prefix+"raft.observer-chan-buffer", 100, "Raft observer channel buffer.")
	fs.BoolVar(&o.RequestVote, prefix+"raft.request-vote", false, "Request a vote in raft elections.")
	fs.BoolVar(&o.RequestObserver, prefix+"raft.request-observer", false, "Request to be an observer in raft.")
	fs.IntVar(&o.HeartbeatPurgeThreshold, prefix+"raft.heartbeat-purge-threshold", 25, "Raft heartbeat purge threshold.")
	fs.BoolVar(&o.PreferIPv6, prefix+"raft.prefer-ipv6", false, "Prefer IPv6 connections for the raft transport.")
	fs.StringVar(&o.LogLevel, prefix+"raft.log-level", "info", "Raft log level.")
}

// Validate validates the options.
func (o *RaftOptions) Validate() error {
	if o.ListenAddress == "" {
		return fmt.Errorf("raft.listen-address is required")
	}
	_, _, err := net.SplitHostPort(o.ListenAddress)
	if err != nil {
		return fmt.Errorf("raft.listen-address is invalid: %w", err)
	}
	if !o.InMemory && o.DataDir == "" {
		return fmt.Errorf("raft.data-dir is required")
	}
	return nil
}

// RaftListenPort returns the listen port for the raft transport.
func (o *Config) RaftListenPort() int {
	_, port, err := net.SplitHostPort(o.Raft.ListenAddress)
	if err != nil {
		return 0
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return p
}

// IsRaftMember returns true if the node is a raft member.
func (o *Config) IsRaftMember() bool {
	return o.Bootstrap.Enabled || o.Raft.RequestVote || o.Raft.RequestObserver
}

// NewRaftNode creates a new raft node for the given mesh instance.
func (o *Config) NewRaftNode(ctx context.Context, conn mesh.Mesh) (raft.Raft, error) {
	nodeid, err := o.NodeID()
	if err != nil {
		return nil, err
	}
	if !o.IsRaftMember() {
		// We return a passthrough raft
		return raft.NewPassthrough(ctx, nodeid, conn), nil
	}
	opts := raft.NewOptions(nodeid)
	opts.DataDir = o.Raft.DataDir
	opts.InMemory = o.Raft.InMemory
	opts.ConnectionPoolCount = o.Raft.ConnectionPoolCount
	opts.ConnectionTimeout = o.Raft.ConnectionTimeout
	opts.HeartbeatTimeout = o.Raft.HeartbeatTimeout
	opts.ElectionTimeout = o.Raft.ElectionTimeout
	opts.ApplyTimeout = o.Raft.ApplyTimeout
	opts.CommitTimeout = o.Raft.CommitTimeout
	opts.MaxAppendEntries = o.Raft.MaxAppendEntries
	opts.LeaderLeaseTimeout = o.Raft.LeaderLeaseTimeout
	opts.SnapshotInterval = o.Raft.SnapshotInterval
	opts.SnapshotThreshold = o.Raft.SnapshotThreshold
	opts.SnapshotRetention = o.Raft.SnapshotRetention
	opts.ObserverChanBuffer = o.Raft.ObserverChanBuffer
	opts.LogLevel = o.Raft.LogLevel
	return raft.New(ctx, opts), nil
}

// NewRaftStartOptions creates a new start options for the current configuration.
func (o *Config) NewRaftStartOptions(conn mesh.Mesh) (opts raft.StartOptions, err error) {
	if !o.Raft.RequestVote && !o.Raft.RequestObserver && !o.Bootstrap.Enabled {
		// We don't actually start raft
		return
	}
	raftTransport, err := o.NewRaftTransport(conn)
	if err != nil {
		return opts, fmt.Errorf("create raft transport: %w", err)
	}
	storage, err := o.NewDualStorage()
	if err != nil {
		return opts, fmt.Errorf("create raft storage: %w", err)
	}
	opts.Transport = raftTransport
	opts.MeshStorage = storage
	opts.RaftStorage = storage
	return
}

// NewRaftTransport creates a new raft transport for the current configuration.
func (o *Config) NewRaftTransport(conn mesh.Mesh) (transport.RaftTransport, error) {
	return tcp.NewRaftTransport(conn, tcp.RaftTransportOptions{
		Addr:    o.Raft.ListenAddress,
		MaxPool: o.Raft.ConnectionPoolCount,
		Timeout: o.Raft.ConnectionTimeout,
	})
}

// NewDualStorage creates a new mesh and raft storage for the current configuration.
func (o *Config) NewDualStorage() (storage.DualStorage, error) {
	if !o.IsRaftMember() {
		// We shouldn't get here, but we'll return a simple in-memory storage
		return memory.New(), nil
	}
	if o.Raft.InMemory {
		st, err := nutsdb.New(nutsdb.Options{InMemory: true})
		if err != nil {
			return nil, fmt.Errorf("create in-memory storage: %w", err)
		}
		return st, nil
	}
	// Make sure the data directory exists
	dataDir := filepath.Join(o.Raft.DataDir, "data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	// If we are forcing bootstrap, delete the data directory
	if o.Bootstrap.Force {
		if err := os.RemoveAll(dataDir); err != nil {
			return nil, fmt.Errorf("remove data directory: %w", err)
		}
	}
	st, err := nutsdb.New(nutsdb.Options{
		DiskPath: dataDir,
	})
	if err != nil {
		return nil, fmt.Errorf("create raft storage: %w", err)
	}
	return st, nil
}
