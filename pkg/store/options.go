/*
Copyright 2023.

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

package store

import (
	"errors"
	"flag"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	"golang.org/x/exp/slog"

	"gitlab.com/webmesh/node/pkg/util"
)

const (
	NodeIDEnvVar              = "STORE_NODE_ID"
	DataDirEnvVar             = "STORE_DATA_DIR"
	AdvertiseAddressEnvVar    = "STORE_ADVERTISE_ADDRESS"
	ConnectionPoolCountEnvVar = "STORE_CONNECTION_POOL_COUNT"
	ConnectionTimeoutEnvVar   = "STORE_CONNECTION_TIMEOUT"
	HeartbeatTimeoutEnvVar    = "STORE_HEARTBEAT_TIMEOUT"
	ElectionTimeoutEnvVar     = "STORE_ELECTION_TIMEOUT"
	ApplyTimeoutEnvVar        = "STORE_APPLY_TIMEOUT"
	CommitTimeoutEnvVar       = "STORE_COMMIT_TIMEOUT"
	MaxAppendEntriesEnvVar    = "STORE_MAX_APPEND_ENTRIES"
	LeaderLeaseTimeoutEnvVar  = "STORE_LEADER_LEASE_TIMEOUT"
	SnapshotIntervalEnvVar    = "STORE_SNAPSHOT_INTERVAL"
	SnapshotThresholdEnvVar   = "STORE_SNAPSHOT_THRESHOLD"
	SnapshotRetentionEnvVar   = "STORE_SNAPSHOT_RETENTION"
	BootstrapEnvVar           = "STORE_BOOTSTRAP"
	IPv4NetworkEnvVar         = "STORE_BOOTSTRAP_IPV4_NETWORK"
	JoinEnvVar                = "STORE_JOIN"
	JoinAsVoterEnvVar         = "STORE_JOIN_AS_VOTER"
	MaxJoinRetriesEnvVar      = "STORE_MAX_JOIN_RETRIES"
	JoinTimeoutEnvVar         = "STORE_JOIN_TIMEOUT"
	ForceNewClusterEnvVar     = "STORE_FORCE_BOOTSTRAP"
	RaftLogLevelEnvVar        = "STORE_RAFT_LOG_LEVEL"
	RaftPreferIPv6EnvVar      = "STORE_RAFT_PREFER_IPV6"
	ObserverChanBufferEnvVar  = "STORE_OBSERVER_CHAN_BUFFER"
	GRPCAdvertisePortEnvVar   = "STORE_GRPC_ADVERTISE_PORT"
	NoIPv4EnvVar              = "STORE_NO_IPV4"
	NoIPv6EnvVar              = "STORE_NO_IPV6"

	// LogFile is the raft log file.
	LogFile = "raft-log.dat"
	// StableStoreFile is the raft stable store file.
	StableStoreFile = "raft-stable-store.dat"
	// DataFile is the data file.
	DataFile = "data.sqlite"
	// LocalDataFile is the local data file.
	LocalDataFile = "local.sqlite"
)

// Options are the options for the store.
type Options struct {
	// NodeID is the node ID.
	NodeID string
	// DataDir is the directory to store data in.
	DataDir string
	// AdvertiseAddress is the initial address to advertise for raft consensus.
	AdvertiseAddress string
	// ConnectionPoolCount is the number of connections to pool.
	// If 0, no connection pooling is used.
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
	// Join is the address of a node to join.
	Join string
	// MaxJoinRetries is the maximum number of join retries.
	MaxJoinRetries int
	// JoinTimeout is the timeout for joining.
	JoinTimeout time.Duration
	// JoinAsVoter is the join as voter flag.
	JoinAsVoter bool
	// Bootstrap is the bootstrap flag. If true, the node will
	// only bootstrap a new cluster if no data is found. To force
	// bootstrap, set ForceBootstrap to true.
	Bootstrap bool
	// BootstrapIPv4Network is the IPv4 network of the mesh to write to the database
	// when bootstraping a new cluster.
	BootstrapIPv4Network string
	// ForceBootstrap is the force new bootstrap.
	ForceBootstrap bool
	// RaftLogLevel is the log level for the raft backend.
	RaftLogLevel string
	// RaftPreferIPv6 is the prefer IPv6 flag.
	RaftPreferIPv6 bool
	// GRPCAdvertisePort is the port to advertise for gRPC.
	GRPCAdvertisePort int
	// NoIPv4 is the no IPv4 flag.
	NoIPv4 bool
	// NoIPv6 is the no IPv6 flag.
	NoIPv6 bool
}

// NewOptions returns new options with sensible defaults.
func NewOptions() *Options {
	return &Options{
		DataDir:              "/var/lib/webmesh/store",
		AdvertiseAddress:     "localhost:9443",
		ConnectionTimeout:    time.Second * 2,
		HeartbeatTimeout:     time.Second * 2,
		ElectionTimeout:      time.Second * 2,
		ApplyTimeout:         time.Second * 10,
		CommitTimeout:        time.Second * 15,
		LeaderLeaseTimeout:   time.Second * 2,
		SnapshotInterval:     time.Minute * 5,
		SnapshotThreshold:    50,
		MaxAppendEntries:     16,
		SnapshotRetention:    3,
		MaxJoinRetries:       10,
		JoinTimeout:          time.Minute,
		ObserverChanBuffer:   100,
		BootstrapIPv4Network: "172.16.0.0/12",
	}
}

const hostnameFlagDefault = "<hostname>"

// BindFlags binds the options to the flags.
func (o *Options) BindFlags(fl *flag.FlagSet) {
	fl.StringVar(&o.NodeID, "store.node-id", util.GetEnvDefault(NodeIDEnvVar, hostnameFlagDefault),
		`Store node ID. If not set, the ID comes from the following decision tree.
	1. If mTLS is enabled, the node ID is the CN of the client certificate.
	2. If mTLS is not enabled, the node ID is the hostname of the machine.
	3. If the hostname is not available, the node ID is a random UUID (should only be used for testing).`)
	fl.StringVar(&o.DataDir, "store.data-dir", util.GetEnvDefault(DataDirEnvVar, "/var/lib/webmesh/store"),
		"Store data directory.")
	fl.StringVar(&o.AdvertiseAddress, "store.advertise-address", util.GetEnvDefault(AdvertiseAddressEnvVar, "localhost:9443"),
		`Raft advertise address. Required when bootstrapping a new cluster,
but will be replaced with the wireguard address after bootstrapping.`)
	fl.IntVar(&o.ConnectionPoolCount, "store.connection-pool-count", util.GetEnvIntDefault(ConnectionPoolCountEnvVar, 0),
		"Raft connection pool count.")
	fl.DurationVar(&o.ConnectionTimeout, "store.connection-timeout", util.GetEnvDurationDefault(ConnectionTimeoutEnvVar, time.Second*2),
		"Raft connection timeout.")
	fl.DurationVar(&o.HeartbeatTimeout, "store.heartbeat-timeout", util.GetEnvDurationDefault(HeartbeatTimeoutEnvVar, time.Second*2),
		"Raft heartbeat timeout.")
	fl.DurationVar(&o.ElectionTimeout, "store.election-timeout", util.GetEnvDurationDefault(ElectionTimeoutEnvVar, time.Second*2),
		"Raft election timeout.")
	fl.DurationVar(&o.ApplyTimeout, "store.apply-timeout", util.GetEnvDurationDefault(ApplyTimeoutEnvVar, time.Second*10),
		"Raft apply timeout.")
	fl.DurationVar(&o.CommitTimeout, "store.commit-timeout", util.GetEnvDurationDefault(CommitTimeoutEnvVar, time.Second*15),
		"Raft commit timeout.")
	fl.IntVar(&o.MaxAppendEntries, "store.max-append-entries", util.GetEnvIntDefault(MaxAppendEntriesEnvVar, 16),
		"Raft max append entries.")
	fl.DurationVar(&o.LeaderLeaseTimeout, "store.leader-lease-timeout", util.GetEnvDurationDefault(LeaderLeaseTimeoutEnvVar, time.Second*2),
		"Raft leader lease timeout.")
	fl.DurationVar(&o.SnapshotInterval, "store.snapshot-interval", util.GetEnvDurationDefault(SnapshotIntervalEnvVar, time.Minute*5),
		"Raft snapshot interval.")
	fl.Uint64Var(&o.SnapshotThreshold, "store.snapshot-threshold", uint64(util.GetEnvIntDefault(SnapshotThresholdEnvVar, 50)),
		"Raft snapshot threshold.")
	fl.Uint64Var(&o.SnapshotRetention, "store.snapshot-retention", uint64(util.GetEnvIntDefault(SnapshotRetentionEnvVar, 3)),
		"Raft snapshot retention.")
	fl.StringVar(&o.Join, "store.join", util.GetEnvDefault(JoinEnvVar, ""),
		"Address of a node to join.")
	fl.IntVar(&o.MaxJoinRetries, "store.max-join-retries", util.GetEnvIntDefault(MaxJoinRetriesEnvVar, 10),
		"Maximum number of join retries.")
	fl.DurationVar(&o.JoinTimeout, "store.join-timeout", util.GetEnvDurationDefault(JoinTimeoutEnvVar, time.Minute),
		"Join timeout.")
	fl.BoolVar(&o.JoinAsVoter, "store.join-as-voter", util.GetEnvDefault(JoinAsVoterEnvVar, "false") == "true",
		"Join the cluster as a voter. Default behavior is to join as an observer.")
	fl.BoolVar(&o.Bootstrap, "store.bootstrap", util.GetEnvDefault(BootstrapEnvVar, "false") == "true",
		"Bootstrap the cluster.")
	fl.StringVar(&o.BootstrapIPv4Network, "store.bootstrap-ipv4-network", util.GetEnvDefault(IPv4NetworkEnvVar, "172.16.0.0/12"),
		"IPv4 network of the mesh to write to the database when bootstraping a new cluster.")
	fl.BoolVar(&o.ForceBootstrap, "store.force-bootstrap", util.GetEnvDefault(ForceNewClusterEnvVar, "false") == "true",
		"Force bootstrapping a new cluster even if data is present.")
	fl.StringVar(&o.RaftLogLevel, "store.raft-log-level", util.GetEnvDefault(RaftLogLevelEnvVar, "info"),
		"Raft log level.")
	fl.BoolVar(&o.RaftPreferIPv6, "store.raft-prefer-ipv6", util.GetEnvDefault(RaftPreferIPv6EnvVar, "false") == "true",
		"Prefer IPv6 when connecting to raft peers.")
	fl.IntVar(&o.ObserverChanBuffer, "store.observer-chan-buffer", util.GetEnvIntDefault(ObserverChanBufferEnvVar, 100),
		"Raft observer channel buffer size.")
	fl.IntVar(&o.GRPCAdvertisePort, "store.grpc-advertise-port", util.GetEnvIntDefault(GRPCAdvertisePortEnvVar, 8443),
		"GRPC advertise port.")
	fl.BoolVar(&o.NoIPv4, "store.no-ipv4", util.GetEnvDefault(NoIPv4EnvVar, "false") == "true",
		"Disable IPv4 for the raft transport.")
	fl.BoolVar(&o.NoIPv6, "store.no-ipv6", util.GetEnvDefault(NoIPv6EnvVar, "false") == "true",
		"Disable IPv6 for the raft transport.")
}

// Validate validates the options.
func (o *Options) Validate() error {
	if o.DataDir == "" {
		return errors.New("data directory is required")
	}
	if !o.Bootstrap && o.Join == "" {
		return errors.New("one of bootstrap or join address is required")
	}
	if o.Bootstrap && o.AdvertiseAddress == "" {
		return errors.New("advertise address is required for bootstrapping")
	}
	if o.Bootstrap && o.BootstrapIPv4Network == "" {
		return errors.New("bootstrap IPv4 network is required for bootstrapping")
	}
	if o.ConnectionPoolCount < 0 {
		return errors.New("connection pool count must be >= 0")
	}
	if o.ConnectionTimeout < 0 {
		return errors.New("connection timeout must be >= 0")
	}
	if o.HeartbeatTimeout < 0 {
		return errors.New("heartbeat timeout must be >= 0")
	}
	if o.ElectionTimeout < 0 {
		return errors.New("election timeout must be >= 0")
	}
	if o.CommitTimeout < 0 {
		return errors.New("commit timeout must be >= 0")
	}
	if o.MaxAppendEntries < 0 {
		return errors.New("max append entries must be >= 0")
	}
	if o.LeaderLeaseTimeout < 0 {
		return errors.New("leader lease timeout must be >= 0")
	}
	if o.SnapshotInterval < 0 {
		return errors.New("snapshot interval must be >= 0")
	}
	if o.MaxJoinRetries <= 0 {
		return errors.New("max join retries must be > 0")
	}
	return nil
}

// RaftConfig returns the raft config from the options.
func (o *Options) RaftConfig(id raft.ServerID) *raft.Config {
	config := raft.DefaultConfig()
	config.LocalID = id
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
	config.LogLevel = hclog.LevelFromString(o.RaftLogLevel).String()
	config.Logger = o.RaftLogger("raft")
	return config
}

// RaftLogger returns a logger for raft operations.
func (o *Options) RaftLogger(name string) hclog.Logger {
	return &hclogAdapter{
		Logger: slog.Default().With("component", name),
		level:  o.RaftLogLevel,
	}
}

// LogFilePath returns the log file path.
func (o *Options) LogFilePath() string {
	return filepath.Join(o.DataDir, LogFile)
}

// StableStoreFilePath returns the stable store file path.
func (o *Options) StableStoreFilePath() string {
	return filepath.Join(o.DataDir, StableStoreFile)
}

// DataFilePath returns the data file path.
func (o *Options) DataFilePath() string {
	return filepath.Join(o.DataDir, DataFile)
}

// LocalDataFilePath returns the local file path.
func (o *Options) LocalDataFilePath() string {
	return filepath.Join(o.DataDir, LocalDataFile)
}
