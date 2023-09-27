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

package raftstorage

import (
	"runtime"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
)

// DefaultDataDir is the default data directory.
var DefaultDataDir = func() string {
	if runtime.GOOS == "windows" {
		return "C:\\ProgramData\\webmesh\\store"
	}
	return "/var/lib/webmesh/store"
}()

const (
	// DefaultListenPort is the default raft listen port
	DefaultListenPort = 9000
	// DefaultListenAddress is the default raft listen address
	DefaultListenAddress = "[::]:9000"
	// DefaultBarrierThreshold is the threshold for sending a barrier after
	// a write operation.
	DefaultBarrierThreshold = 10
)

// Options are the raft options.
type Options struct {
	// NodeID is the node ID.
	NodeID string
	// Transport is the Raft transport to use for communicating with
	// other Raft nodes.
	Transport transport.RaftTransport
	// DataDir is the directory to store data in.
	DataDir string
	// ClearDataDir is if the data directory should be cleared on startup.
	ClearDataDir bool
	// InMemory is if the store should be in memory. This should only be used for testing and ephemeral nodes.
	InMemory bool
	// ConnectionPoolCount is the number of connections to pool. If 0, no connection pooling is used.
	ConnectionPoolCount int
	// ConnectionTimeout is the timeout for connections.
	ConnectionTimeout time.Duration
	// HeartbeatTimeout is the timeout for heartbeats.
	HeartbeatTimeout time.Duration
	// ElectionTimeout is the timeout for elections.
	ElectionTimeout time.Duration
	// ApplyTimeout is the timeout for applying.
	ApplyTimeout time.Duration
	// CommitTimeout is the timeout for committing.
	CommitTimeout time.Duration
	// MaxAppendEntries is the maximum number of append entries.
	MaxAppendEntries int
	// LeaderLeaseTimeout is the timeout for leader leases.
	LeaderLeaseTimeout time.Duration
	// SnapshotInterval is the interval to take snapshots.
	SnapshotInterval time.Duration
	// SnapshotThreshold is the threshold to take snapshots.
	SnapshotThreshold uint64
	// SnapshotRetention is the number of snapshots to retain.
	SnapshotRetention uint64
	// ObserverChanBuffer is the buffer size for the observer channel.
	ObserverChanBuffer int
	// BarrierThreshold is the threshold for sending a barrier after a write operation.
	BarrierThreshold int32
	// LogLevel is the log level for the raft backend.
	LogLevel string
}

// NewOptions returns new raft options with sensible defaults.
func NewOptions(nodeID string, transport transport.RaftTransport) Options {
	return Options{
		NodeID:             nodeID,
		Transport:          transport,
		DataDir:            DefaultDataDir,
		ConnectionTimeout:  time.Second * 3,
		HeartbeatTimeout:   time.Second * 3,
		ElectionTimeout:    time.Second * 3,
		ApplyTimeout:       time.Second * 15,
		CommitTimeout:      time.Second * 15,
		LeaderLeaseTimeout: time.Second * 3,
		SnapshotInterval:   time.Minute * 3,
		SnapshotThreshold:  5,
		MaxAppendEntries:   15,
		SnapshotRetention:  3,
		ObserverChanBuffer: 100,
		BarrierThreshold:   DefaultBarrierThreshold,
		LogLevel:           "info",
	}
}

// RaftConfig builds a raft config.
func (o *Options) RaftConfig(ctx context.Context, nodeID string) *raft.Config {
	config := raft.DefaultConfig()
	config.LocalID = raft.ServerID(nodeID)
	config.ShutdownOnRemove = true
	if o.HeartbeatTimeout != 0 {
		config.HeartbeatTimeout = o.HeartbeatTimeout
	}
	if o.ElectionTimeout != 0 {
		config.ElectionTimeout = o.ElectionTimeout
	}
	if o.CommitTimeout != 0 {
		config.CommitTimeout = o.CommitTimeout
	}
	if o.MaxAppendEntries != 0 {
		config.MaxAppendEntries = o.MaxAppendEntries
	}
	if o.LeaderLeaseTimeout != 0 {
		config.LeaderLeaseTimeout = o.LeaderLeaseTimeout
	}
	if o.SnapshotInterval != 0 {
		config.SnapshotInterval = o.SnapshotInterval
	}
	if o.SnapshotThreshold != 0 {
		config.SnapshotThreshold = o.SnapshotThreshold
	}
	if o.BarrierThreshold <= 0 {
		o.BarrierThreshold = DefaultBarrierThreshold
	}
	config.LogLevel = hclog.LevelFromString(o.LogLevel).String()
	config.Logger = logging.NewHCLogAdapter("", o.LogLevel, context.LoggerFrom(ctx).With("component", "raft"))
	return config
}
