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

// Package store provides raft consensus and data storage for webmesh nodes.
package store

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/raft"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"gitlab.com/webmesh/node/pkg/firewall"
	"gitlab.com/webmesh/node/pkg/meshdb"
	"gitlab.com/webmesh/node/pkg/meshdb/models/localdb"
	"gitlab.com/webmesh/node/pkg/meshdb/snapshots"
	"gitlab.com/webmesh/node/pkg/store/streamlayer"
	"gitlab.com/webmesh/node/pkg/wireguard"
)

var (
	// ErrNotLeader is returned when a Raft request is made to a
	// non-leader node.
	ErrNotLeader = fmt.Errorf("not leader")
	// ErrNotOpen is returned when a Raft request is made to a
	// non-open store.
	ErrNotOpen = fmt.Errorf("not open")
	// ErrOpen is returned when a store is already open.
	ErrOpen = fmt.Errorf("already open")
	// ErrNotReady is returned when a store is not ready.
	ErrNotReady = fmt.Errorf("not ready")
)

// Store is the store interface.
type Store interface {
	// ID returns the node ID.
	ID() string
	// Open opens the store.
	Open() error
	// IsOpen returns true if the store is open.
	IsOpen() bool
	// Close closes the store.
	Close() error
	// Ready returns true if the store is ready to serve requests.
	Ready() bool
	// ConfigureWireguard configures the wireguard interface. This is normally called
	// when the store is opened through joining a cluster, but can be called again to
	// reconfigure the interface or after a bootstrap.
	ConfigureWireguard(ctx context.Context, key wgtypes.Key, networkv4, networkv6 netip.Prefix) error
	// RefreshWireguardPeers refreshes the wireguard peers. This is normally called
	// on an interval or when peer observations happen on the cluster. It can also
	// be called manually to force a refresh.
	RefreshWireguardPeers(ctx context.Context) error
	// ReadyNotify returns a channel that is closed when the store is ready
	// to serve requests. Ready is defined as having a leader.
	ReadyNotify(ctx context.Context) <-chan struct{}
	// ReadyError returns a channel that will receive an error if the store
	// fails to become ready. This is only applicable during an initial
	// bootstrap. If the store is already bootstrapped then this channel
	// will block until the store is ready and then return nil.
	ReadyError() <-chan error
	// State returns the current Raft state.
	State() raft.RaftState
	// IsLeader returns true if this node is the Raft leader.
	IsLeader() bool
	// Leader returns the current Raft leader ID.
	Leader() (raft.ServerID, error)
	// LeaderAddr returns the current Raft leader's raft address.
	LeaderAddr() (string, error)
	// LeaderRPCAddr returns the current Raft leader's gRPC address.
	LeaderRPCAddr(ctx context.Context) (string, error)
	// Stepdown forces this node to relinquish leadership to another node in
	// the cluster. If wait is true then this method will block until the
	// leadership transfer is complete and return any error that ocurred.
	Stepdown(wait bool) error
	// AddNonVoter adds a non-voting node to the cluster with timeout enforced by the context.
	AddNonVoter(ctx context.Context, id string, addr string) error
	// AddVoter adds a voting node to the cluster with timeout enforced by the context.
	AddVoter(ctx context.Context, id string, addr string) error
	// DemoteVoter demotes a voting node to a non-voting node with timeout enforced by the context.
	DemoteVoter(ctx context.Context, id string) error
	// RemoveServer removes a peer from the cluster with timeout enforced by the context.
	RemoveServer(ctx context.Context, id string, wait bool) error
	// DB returns a DB interface for use by the application. This
	// interface will ensure consistency with the Raft log. Transactions
	// are executed in the order they are received by the leader node.
	DB() meshdb.DBTX
	// ReadDB returns a DB interface for use by the application. This
	// interface will not ensure consistency with the Raft log. It is
	// intended for use in read-only operations that do not require
	// immediate consistency. It takes a read lock on the data store
	// to ensure that no modifications are happening while the transaction
	// is in progress and that SQLite itself is not busy.
	ReadDB() meshdb.DBTX
	// LocalDB returns a DB interface for use by the application. This
	// interface will not ensure consistency with the Raft log. It is
	// intended for use with the node_local database which is not replicated
	// across the cluster.
	LocalDB() localdb.DBTX
	// Raft returns the Raft interface. Note that the returned value
	// may be nil if the store is not open.
	Raft() *raft.Raft
	// Wireguard returns the Wireguard interface. Note that the returned value
	// may be nil if the store is not open.
	Wireguard() wireguard.Interface
}

// New creates a new store.
func New(sl streamlayer.StreamLayer, opts *Options, wgOpts *wireguard.Options) Store {
	log := slog.Default().With(slog.String("component", "store"))
	nodeID := opts.NodeID
	if nodeID == "" || nodeID == hostnameFlagDefault {
		// First check if we are using mTLS.
		if !sl.Insecure() && sl.TLSConfig().ClientAuth == tls.RequireAndVerifyClientCert {
			// If so, use the certificate's CN as the node ID.
			nodeID = sl.TLSConfig().Certificates[0].Leaf.Subject.CommonName
			log.Info("using CN as node ID",
				slog.String("node-id", string(nodeID)))
		} else {
			// Try to retrieve the system hostname
			hostname, err := os.Hostname()
			if err != nil {
				log.Warn("unable to retrieve system hostname, generating random UUID for node ID",
					slog.String("error", err.Error()))
				nodeID = uuid.NewString()
			} else {
				nodeID = hostname
				log.Info("using system hostname as node ID",
					slog.String("node-id", string(nodeID)))
			}
		}
	}
	return &store{
		sl:            sl,
		opts:          opts,
		wgopts:        wgOpts,
		nodeID:        raft.ServerID(nodeID),
		raftLogFormat: RaftLogFormat(opts.RaftLogFormat),
		readyErr:      make(chan error, 2),
		log:           log.With(slog.String("node-id", string(nodeID))),
	}
}

type store struct {
	sl     streamlayer.StreamLayer
	opts   *Options
	wgopts *wireguard.Options
	log    *slog.Logger

	nodeID raft.ServerID

	readyErr       chan error
	firstBootstrap bool

	raft          *raft.Raft
	raftIndex     atomic.Uint64
	raftTransport *raft.NetworkTransport
	raftSnapshots raft.SnapshotStore
	logDB         LogStoreCloser
	stableDB      StableStoreCloser
	raftLogFormat RaftLogFormat
	snapshotter   snapshots.Snapshotter

	observerChan                chan raft.Observation
	observer                    *raft.Observer
	observerClose, observerDone chan struct{}

	weakData, raftData *sql.DB
	localData          *sql.DB
	dataAppliedIndex   atomic.Uint64
	dataMux            sync.RWMutex

	wg    wireguard.Interface
	fw    firewall.Firewall
	wgmux sync.Mutex

	open atomic.Bool
}

// ID returns the node ID.
func (s *store) ID() string {
	return string(s.nodeID)
}

// IsOpen returns true if the store is open.
func (s *store) IsOpen() bool {
	return s.open.Load()
}

// DB returns a DB interface for use by the application. This
// interface will ensure consistency with the Raft log. Transactions
// are executed in the order they are received by the leader node.
func (s *store) DB() meshdb.DBTX {
	// Locks are taken during the application of log entries
	return s.raftData
}

// ReadDB returns a DB interface for use by the application. This
// interface will not ensure consistency with the Raft log. It is
// intended for use in read-only operations that do not require
// immediate consistency. It takes a read lock on the data store
// to ensure that no modifications are happening while the transaction
// is in progress and that SQLite itself is not busy.
func (s *store) ReadDB() meshdb.DBTX {
	return &lockableDB{DB: s.weakData, mux: s.dataMux.RLocker()}
}

// LocalDB returns a DB interface for use by the application. This
// interface will not ensure consistency with the Raft log. It is
// intended for use with the node_local table which is not replicated
// across the cluster.
func (s *store) LocalDB() localdb.DBTX {
	return &lockableDB{DB: s.localData, mux: &s.dataMux}
}

// Raft returns the Raft interface.
func (s *store) Raft() *raft.Raft { return s.raft }

// Wireguard returns the Wireguard interface. Note that the returned value
// may be nil if the store is not open.
func (s *store) Wireguard() wireguard.Interface { return s.wg }

// State returns the current Raft state.
func (s *store) State() raft.RaftState {
	if s.raft == nil {
		return raft.Shutdown
	}
	return s.raft.State()
}

// Ready returns true if the store is ready to serve requests. Ready is
// defined as having a leader.
func (s *store) Ready() bool {
	leader, err := s.LeaderAddr()
	return err == nil && leader != ""
}

// ReadyNotify returns a channel that is closed when the store is ready
// to serve requests. Ready is defined as having a leader.
func (s *store) ReadyNotify(ctx context.Context) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if s.Ready() {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
	return ch
}

// ReadyError returns a channel that will receive an error if the store
// fails to become ready or nil. This is only applicable during an initial
// bootstrap. If the store is already bootstrapped then this channel
// will block until the store is ready and then return nil.
func (s *store) ReadyError() <-chan error {
	if !s.firstBootstrap {
		go func() {
			defer close(s.readyErr)
			<-s.ReadyNotify(context.Background())
			s.readyErr <- nil
		}()
	}
	return s.readyErr
}

type LogStoreCloser interface {
	io.Closer
	raft.LogStore
}

type StableStoreCloser interface {
	io.Closer
	raft.StableStore
}
