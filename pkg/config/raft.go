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
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport/tcp"
	"github.com/webmeshproj/webmesh/pkg/meshnode"
	"github.com/webmeshproj/webmesh/pkg/storage/providers/raftstorage"
)

// RaftOptions are options for the raft backend.
type RaftOptions struct {
	// ListenAddress is the address to listen on.
	ListenAddress string `koanf:"listen-address,omitempty"`
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
	// HeartbeatPurgeThreshold is the threshold of failed heartbeats before purging a peer.
	HeartbeatPurgeThreshold int `koanf:"heartbeat-purge-threshold,omitempty"`
}

// NewRaftOptions returns a new RaftOptions with the default values.
func NewRaftOptions() RaftOptions {
	return RaftOptions{
		ListenAddress:           raftstorage.DefaultListenAddress,
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
		HeartbeatPurgeThreshold: 25,
	}
}

// BindFlags binds the flags.
func (o *RaftOptions) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.StringVar(&o.ListenAddress, prefix+"listen-address", o.ListenAddress, "Raft listen address.")
	fs.IntVar(&o.ConnectionPoolCount, prefix+"connection-pool-count", o.ConnectionPoolCount, "Raft connection pool count.")
	fs.DurationVar(&o.ConnectionTimeout, prefix+"connection-timeout", o.ConnectionTimeout, "Raft connection timeout.")
	fs.DurationVar(&o.HeartbeatTimeout, prefix+"heartbeat-timeout", o.HeartbeatTimeout, "Raft heartbeat timeout.")
	fs.DurationVar(&o.ElectionTimeout, prefix+"election-timeout", o.ElectionTimeout, "Raft election timeout.")
	fs.DurationVar(&o.ApplyTimeout, prefix+"apply-timeout", o.ApplyTimeout, "Raft apply timeout.")
	fs.DurationVar(&o.CommitTimeout, prefix+"commit-timeout", o.CommitTimeout, "Raft commit timeout.")
	fs.IntVar(&o.MaxAppendEntries, prefix+"max-append-entries", o.MaxAppendEntries, "Raft max append entries.")
	fs.DurationVar(&o.LeaderLeaseTimeout, prefix+"leader-lease-timeout", o.LeaderLeaseTimeout, "Raft leader lease timeout.")
	fs.DurationVar(&o.SnapshotInterval, prefix+"snapshot-interval", o.SnapshotInterval, "Raft snapshot interval.")
	fs.Uint64Var(&o.SnapshotThreshold, prefix+"snapshot-threshold", o.SnapshotThreshold, "Raft snapshot threshold.")
	fs.Uint64Var(&o.SnapshotRetention, prefix+"snapshot-retention", o.SnapshotRetention, "Raft snapshot retention.")
	fs.IntVar(&o.ObserverChanBuffer, prefix+"observer-chan-buffer", o.ObserverChanBuffer, "Raft observer channel buffer.")
	fs.IntVar(&o.HeartbeatPurgeThreshold, prefix+"heartbeat-purge-threshold", o.HeartbeatPurgeThreshold, "Raft heartbeat purge threshold.")
}

// Validate validates the options.
func (o *RaftOptions) Validate(dataDir string, inMemory bool) error {
	if o.ListenAddress == "" {
		return fmt.Errorf("raft.listen-address is required")
	}
	_, _, err := net.SplitHostPort(o.ListenAddress)
	if err != nil {
		return fmt.Errorf("raft.listen-address is invalid: %w", err)
	}
	if !inMemory && dataDir == "" {
		return fmt.Errorf("storage.data-dir is required when not running in-memory")
	}
	return nil
}

// NewTransport creates a new raft transport for the current configuration.
func (o *RaftOptions) NewTransport(conn meshnode.Node) (transport.RaftTransport, error) {
	return tcp.NewRaftTransport(conn, tcp.RaftTransportOptions{
		Addr:    o.ListenAddress,
		MaxPool: o.ConnectionPoolCount,
		Timeout: o.ConnectionTimeout,
	})
}

// ListenPort returns the listen port.
func (o *RaftOptions) ListenPort() int {
	addr, err := netip.ParseAddrPort(o.ListenAddress)
	if err != nil {
		return 0
	}
	return int(addr.Port())
}
