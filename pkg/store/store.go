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
	"crypto/x509"
	"database/sql"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/raft"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/node/pkg/meshdb"
	"github.com/webmeshproj/node/pkg/meshdb/models"
	"github.com/webmeshproj/node/pkg/meshdb/models/localdb"
	"github.com/webmeshproj/node/pkg/meshdb/snapshots"
	"github.com/webmeshproj/node/pkg/net/firewall"
	"github.com/webmeshproj/node/pkg/net/wireguard"
	"github.com/webmeshproj/node/pkg/plugins"
	"github.com/webmeshproj/node/pkg/store/streamlayer"
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
	// ReadyNotify returns a channel that is closed when the store is ready
	// to serve requests. Ready is defined as having a leader.
	ReadyNotify(ctx context.Context) <-chan struct{}
	// ReadyError returns a channel that will receive an error if the store
	// fails to become ready. This is only applicable during an initial
	// bootstrap. If the store is already bootstrapped then this channel
	// will block until the store is ready and then return nil.
	ReadyError(ctx context.Context) <-chan error
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
	// Plugins returns the plugin manager.
	Plugins() plugins.Manager
}

// TestStore is a test store interface.
type TestStore interface {
	// Store is the base store interface.
	Store
	// Clear resets the data in the store to a clean state.
	Clear() error
}

// New creates a new store.
func New(opts *Options) (Store, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	pluginManager, err := plugins.New(context.Background(), opts.Plugins)
	if err != nil {
		return nil, fmt.Errorf("failed to load plugins: %w", err)
	}
	nodeID := opts.Mesh.NodeID
	var tlsConfig *tls.Config
	if !opts.TLS.Insecure {
		var err error
		tlsConfig, err = opts.TLSConfig()
		if err != nil {
			return nil, err
		}
	}
	log := slog.Default().With(slog.String("component", "store"))
	if nodeID == "" || nodeID == hostnameFlagDefault {
		// First check if we are using mTLS.
		if tlsConfig != nil {
			if len(tlsConfig.Certificates) == 0 {
				log.Warn("no client certificates provided, generating random UUID for node ID")
				nodeID = uuid.NewString()
			} else {
				clientCert := tlsConfig.Certificates[0]
				leaf, err := x509.ParseCertificate(clientCert.Certificate[0])
				if err != nil {
					log.Warn("unable to parse client certificate, generating random UUID for node ID",
						slog.String("error", err.Error()))
					nodeID = uuid.NewString()
				} else {
					nodeID = leaf.Subject.CommonName
					log.Info("using CN as node ID", slog.String("node-id", nodeID))
				}
			}
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
	sl, err := streamlayer.New(&streamlayer.Options{
		ListenAddress: opts.Raft.ListenAddress,
	})
	if err != nil {
		return nil, err
	}
	return &store{
		sl:            sl,
		opts:          opts,
		tlsConfig:     tlsConfig,
		plugins:       pluginManager,
		nodeID:        raft.ServerID(nodeID),
		raftLogFormat: RaftLogFormat(opts.Raft.LogFormat),
		readyErr:      make(chan error, 2),
		log:           log.With(slog.String("node-id", string(nodeID))),
	}, nil
}

// NewTestStore creates a new test store and waits for it to be ready.
// The context is used to enforce startup timeouts.
func NewTestStore(ctx context.Context) (TestStore, error) {
	opts := NewOptions()
	opts.Raft.ListenAddress = ":0"
	opts.Raft.InMemory = true
	opts.TLS.Insecure = true
	opts.Bootstrap.Enabled = true
	opts.Mesh.NodeID = uuid.NewString()
	deadline, ok := ctx.Deadline()
	if ok {
		opts.Raft.StartupTimeout = time.Until(deadline)
	}
	st, err := New(opts)
	if err != nil {
		return nil, err
	}
	stor := st.(*store)
	stor.noWG = true
	if err := stor.Open(); err != nil {
		return nil, err
	}
	err = <-stor.ReadyError(ctx)
	if err != nil {
		return nil, err
	}
	return &testStore{stor}, nil
}

type store struct {
	sl   streamlayer.StreamLayer
	opts *Options
	log  *slog.Logger

	nodeID    raft.ServerID
	tlsConfig *tls.Config
	plugins   plugins.Manager

	readyErr       chan error
	firstBootstrap bool

	raft             *raft.Raft
	lastAppliedIndex atomic.Uint64
	raftTransport    *raft.NetworkTransport
	raftSnapshots    raft.SnapshotStore
	logDB            LogStoreCloser
	stableDB         StableStoreCloser
	raftLogFormat    RaftLogFormat
	snapshotter      snapshots.Snapshotter

	observerChan                chan raft.Observation
	observer                    *raft.Observer
	observerClose, observerDone chan struct{}

	weakData, raftData *sql.DB
	localData          *sql.DB
	dataAppliedIndex   atomic.Uint64
	dataMux            sync.RWMutex

	wg           wireguard.Interface
	fw           firewall.Firewall
	masquerading bool
	wgmux        sync.Mutex

	open atomic.Bool

	// a flag set on test stores to indicate skipping wireguard setup
	noWG bool
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

// Plugins returns the plugin manager.
func (s *store) Plugins() plugins.Manager { return s.plugins }

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
// will block until the store is ready and then return nil or the error from
// the context.
func (s *store) ReadyError(ctx context.Context) <-chan error {
	if !s.firstBootstrap {
		go func() {
			defer close(s.readyErr)
			<-s.ReadyNotify(ctx)
			if ctx.Err() != nil {
				s.readyErr <- ctx.Err()
				return
			}
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

type testStore struct {
	*store
}

func (t *testStore) Clear() error {
	err := t.localData.Close()
	if err != nil {
		return err
	}
	err = t.weakData.Close()
	if err != nil {
		return err
	}
	dataPath := "file:raftdata?mode=memory&cache=shared&_foreign_keys=on&_case_sensitive_like=on&synchronous=full"
	localDataPath := "file:localdata?mode=memory&cache=shared"
	t.weakData, err = sql.Open("sqlite", dataPath)
	if err != nil {
		return err
	}
	t.localData, err = sql.Open("sqlite", localDataPath)
	if err != nil {
		return err
	}
	if err = models.MigrateRaftDB(t.weakData); err != nil {
		return fmt.Errorf("raft db migrate: %w", err)
	}
	if err = models.MigrateLocalDB(t.localData); err != nil {
		return fmt.Errorf("local db migrate: %w", err)
	}
	return nil
}
