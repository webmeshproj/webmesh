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

package raft

import (
	"errors"
	"flag"
	"io"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/util"
)

const (
	RaftListenAddressEnvVar   = "RAFT_LISTEN_ADDRESS"
	DataDirEnvVar             = "RAFT_DATA_DIR"
	InMemoryEnvVar            = "RAFT_IN_MEMORY"
	ConnectionPoolCountEnvVar = "RAFT_CONNECTION_POOL_COUNT"
	ConnectionTimeoutEnvVar   = "RAFT_CONNECTION_TIMEOUT"
	HeartbeatTimeoutEnvVar    = "RAFT_HEARTBEAT_TIMEOUT"
	ElectionTimeoutEnvVar     = "RAFT_ELECTION_TIMEOUT"
	ApplyTimeoutEnvVar        = "RAFT_APPLY_TIMEOUT"
	CommitTimeoutEnvVar       = "RAFT_COMMIT_TIMEOUT"
	MaxAppendEntriesEnvVar    = "RAFT_MAX_APPEND_ENTRIES"
	LeaderLeaseTimeoutEnvVar  = "RAFT_LEADER_LEASE_TIMEOUT"
	SnapshotIntervalEnvVar    = "RAFT_SNAPSHOT_INTERVAL"
	SnapshotThresholdEnvVar   = "RAFT_SNAPSHOT_THRESHOLD"
	SnapshotRetentionEnvVar   = "RAFT_SNAPSHOT_RETENTION"
	ObserverChanBufferEnvVar  = "RAFT_OBSERVER_CHAN_BUFFER"
	RaftLogLevelEnvVar        = "RAFT_LOG_LEVEL"
	RaftPreferIPv6EnvVar      = "RAFT_PREFER_IPV6"
	LeaveOnShutdownEnvVar     = "RAFT_LEAVE_ON_SHUTDOWN"
	StartupTimeoutEnvVar      = "RAFT_STARTUP_TIMEOUT"

	// RaftStorePath is the raft stable and log store directory.
	RaftStorePath = "raft-store"
	// DataStoragePath is the raft data storage directory.
	DataStoragePath = "raft-data"
)

// Options are the raft options.
type Options struct {
	// ListenAddress is the address to listen on for raft.
	ListenAddress string `json:"listen-address,omitempty" yaml:"listen-address,omitempty" toml:"listen-address,omitempty"`
	// DataDir is the directory to store data in.
	DataDir string `json:"data-dir,omitempty" yaml:"data-dir,omitempty" toml:"data-dir,omitempty"`
	// InMemory is if the store should be in memory. This should only be used for testing and ephemeral nodes.
	InMemory bool `json:"in-memory,omitempty" yaml:"in-memory,omitempty" toml:"in-memory,omitempty"`
	// ConnectionPoolCount is the number of connections to pool. If 0, no connection pooling is used.
	ConnectionPoolCount int `json:"connection-pool-count,omitempty" yaml:"connection-pool-count,omitempty" toml:"connection-pool-count,omitempty"`
	// ConnectionTimeout is the timeout for connections.
	ConnectionTimeout time.Duration `json:"connection-timeout,omitempty" yaml:"connection-timeout,omitempty" toml:"connection-timeout,omitempty"`
	// HeartbeatTimeout is the timeout for heartbeats.
	HeartbeatTimeout time.Duration `json:"heartbeat-timeout,omitempty" yaml:"heartbeat-timeout,omitempty" toml:"heartbeat-timeout,omitempty"`
	// ElectionTimeout is the timeout for elections.
	ElectionTimeout time.Duration `json:"election-timeout,omitempty" yaml:"election-timeout,omitempty" toml:"election-timeout,omitempty"`
	// ApplyTimeout is the timeout for applying.
	ApplyTimeout time.Duration `json:"apply-timeout,omitempty" yaml:"apply-timeout,omitempty" toml:"apply-timeout,omitempty"`
	// CommitTimeout is the timeout for committing.
	CommitTimeout time.Duration `json:"commit-timeout,omitempty" yaml:"commit-timeout,omitempty" toml:"commit-timeout,omitempty"`
	// MaxAppendEntries is the maximum number of append entries.
	MaxAppendEntries int `json:"max-append-entries,omitempty" yaml:"max-append-entries,omitempty" toml:"max-append-entries,omitempty"`
	// LeaderLeaseTimeout is the timeout for leader leases.
	LeaderLeaseTimeout time.Duration `json:"leader-lease-timeout,omitempty" yaml:"leader-lease-timeout,omitempty" toml:"leader-lease-timeout,omitempty"`
	// SnapshotInterval is the interval to take snapshots.
	SnapshotInterval time.Duration `json:"snapshot-interval,omitempty" yaml:"snapshot-interval,omitempty" toml:"snapshot-interval,omitempty"`
	// SnapshotThreshold is the threshold to take snapshots.
	SnapshotThreshold uint64 `json:"snapshot-threshold,omitempty" yaml:"snapshot-threshold,omitempty" toml:"snapshot-threshold,omitempty"`
	// SnapshotRetention is the number of snapshots to retain.
	SnapshotRetention uint64 `json:"snapshot-retention,omitempty" yaml:"snapshot-retention,omitempty" toml:"snapshot-retention,omitempty"`
	// ObserverChanBuffer is the buffer size for the observer channel.
	ObserverChanBuffer int `json:"observer-chan-buffer,omitempty" yaml:"observer-chan-buffer,omitempty" toml:"observer-chan-buffer,omitempty"`
	// LogLevel is the log level for the raft backend.
	LogLevel string `json:"log-level,omitempty" yaml:"log-level,omitempty" toml:"log-level,omitempty"`
	// PreferIPv6 is the prefer IPv6 flag.
	PreferIPv6 bool `json:"prefer-ipv6,omitempty" yaml:"prefer-ipv6,omitempty" toml:"prefer-ipv6,omitempty"`
	// LeaveOnShutdown is the leave on shutdown flag.
	LeaveOnShutdown bool `json:"leave-on-shutdown,omitempty" yaml:"leave-on-shutdown,omitempty" toml:"leave-on-shutdown,omitempty"`

	// Below are callbacks used internally or by external packages.
	OnApplyLog        func(ctx context.Context, term, index uint64, log *v1.RaftLogEntry) `json:"-" yaml:"-" toml:"-"`
	OnSnapshotRestore func(ctx context.Context, meta *SnapshotMeta, data io.ReadCloser)   `json:"-" yaml:"-" toml:"-"`
	OnObservation     func(ev Observation)                                                `json:"-" yaml:"-" toml:"-"`
}

// NewOptions returns new raft options with the default values.
func NewOptions() *Options {
	return &Options{
		ListenAddress:      ":9443",
		DataDir:            "/var/lib/webmesh/store",
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
		LogLevel:           "info",
	}
}

// BindFlags binds the flags to the options.
func (o *Options) BindFlags(fl *flag.FlagSet) {
	fl.StringVar(&o.ListenAddress, "raft.listen-address", util.GetEnvDefault(RaftListenAddressEnvVar, ":9443"),
		"Raft listen address.")
	fl.StringVar(&o.DataDir, "raft.data-dir", util.GetEnvDefault(DataDirEnvVar, "/var/lib/webmesh/store"),
		"Store data directory.")
	fl.BoolVar(&o.InMemory, "raft.in-memory", util.GetEnvDefault(InMemoryEnvVar, "false") == "true",
		"Store data in memory. This should only be used for testing and ephemeral nodes.")
	fl.IntVar(&o.ConnectionPoolCount, "raft.connection-pool-count", util.GetEnvIntDefault(ConnectionPoolCountEnvVar, 0),
		"Raft connection pool count.")
	fl.DurationVar(&o.ConnectionTimeout, "raft.connection-timeout", util.GetEnvDurationDefault(ConnectionTimeoutEnvVar, time.Second*3),
		"Raft connection timeout.")
	fl.DurationVar(&o.HeartbeatTimeout, "raft.heartbeat-timeout", util.GetEnvDurationDefault(HeartbeatTimeoutEnvVar, time.Second*3),
		"Raft heartbeat timeout.")
	fl.DurationVar(&o.ElectionTimeout, "raft.election-timeout", util.GetEnvDurationDefault(ElectionTimeoutEnvVar, time.Second*3),
		"Raft election timeout.")
	fl.DurationVar(&o.ApplyTimeout, "raft.apply-timeout", util.GetEnvDurationDefault(ApplyTimeoutEnvVar, time.Second*15),
		"Raft apply timeout.")
	fl.DurationVar(&o.CommitTimeout, "raft.commit-timeout", util.GetEnvDurationDefault(CommitTimeoutEnvVar, time.Second*15),
		"Raft commit timeout.")
	fl.IntVar(&o.MaxAppendEntries, "raft.max-append-entries", util.GetEnvIntDefault(MaxAppendEntriesEnvVar, 15),
		"Raft max append entries.")
	fl.DurationVar(&o.LeaderLeaseTimeout, "raft.leader-lease-timeout", util.GetEnvDurationDefault(LeaderLeaseTimeoutEnvVar, time.Second*3),
		"Raft leader lease timeout.")
	fl.DurationVar(&o.SnapshotInterval, "raft.snapshot-interval", util.GetEnvDurationDefault(SnapshotIntervalEnvVar, time.Minute*3),
		"Raft snapshot interval.")
	fl.Uint64Var(&o.SnapshotThreshold, "raft.snapshot-threshold", uint64(util.GetEnvIntDefault(SnapshotThresholdEnvVar, 5)),
		"Raft snapshot threshold.")
	fl.Uint64Var(&o.SnapshotRetention, "raft.snapshot-retention", uint64(util.GetEnvIntDefault(SnapshotRetentionEnvVar, 3)),
		"Raft snapshot retention.")
	fl.StringVar(&o.LogLevel, "raft.log-level", util.GetEnvDefault(RaftLogLevelEnvVar, "info"),
		"Raft log level.")
	fl.BoolVar(&o.PreferIPv6, "raft.prefer-ipv6", util.GetEnvDefault(RaftPreferIPv6EnvVar, "false") == "true",
		"Prefer IPv6 when connecting to raft peers.")
	fl.IntVar(&o.ObserverChanBuffer, "raft.observer-chan-buffer", util.GetEnvIntDefault(ObserverChanBufferEnvVar, 100),
		"Raft observer channel buffer size.")
	fl.BoolVar(&o.LeaveOnShutdown, "raft.leave-on-shutdown", util.GetEnvDefault(LeaveOnShutdownEnvVar, "false") == "true",
		"Leave the cluster when the server shuts down.")
}

// Validate validates the raft options.
func (o *Options) Validate() error {
	if o == nil {
		return errors.New("raft options are nil")
	}
	if o.DataDir == "" && !o.InMemory {
		return errors.New("data directory is required")
	}
	if o.ConnectionPoolCount < 0 {
		return errors.New("connection pool count must be >= 0")
	}
	if o.ConnectionTimeout <= 0 {
		return errors.New("connection timeout must be > 0")
	}
	if o.HeartbeatTimeout <= 0 {
		return errors.New("heartbeat timeout must be > 0")
	}
	if o.ElectionTimeout <= 0 {
		return errors.New("election timeout must be > 0")
	}
	if o.CommitTimeout <= 0 {
		return errors.New("commit timeout must be > 0")
	}
	if o.MaxAppendEntries <= 0 {
		return errors.New("max append entries must be > 0")
	}
	if o.LeaderLeaseTimeout <= 0 {
		return errors.New("leader lease timeout must be > 0")
	}
	if o.SnapshotInterval <= 0 {
		return errors.New("snapshot interval must be > 0")
	}
	return nil
}

// RaftConfig builds a raft config.
func (o *Options) RaftConfig(nodeID string) *raft.Config {
	config := raft.DefaultConfig()
	config.LocalID = raft.ServerID(nodeID)
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
	config.LogLevel = hclog.LevelFromString(o.LogLevel).String()
	config.Logger = &hclogAdapter{
		Logger: slog.Default().With("component", "raft"),
		level:  o.LogLevel,
	}
	return config
}

// StorePath returns the stable store path.
func (o *Options) StorePath() string {
	return filepath.Join(o.DataDir, RaftStorePath)
}

// DataStoragePath returns the data directory.
func (o *Options) DataStoragePath() string {
	return filepath.Join(o.DataDir, DataStoragePath)
}
