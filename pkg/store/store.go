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
	"golang.org/x/sync/errgroup"

	"github.com/webmeshproj/node/pkg/meshdb"
	"github.com/webmeshproj/node/pkg/meshdb/snapshots"
	"github.com/webmeshproj/node/pkg/meshdb/state"
	"github.com/webmeshproj/node/pkg/net"
	meshnet "github.com/webmeshproj/node/pkg/net"
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

// Store is the store interface. It contains the state of the mesh and manages
// the WireGuard interface.
type Store interface {
	// ID returns the node ID.
	ID() string
	// Open opens the store. This must be called before the store can be used.
	// The Ready functions should be used to determine when the store is ready
	// to serve requests, after which the Wireguard interface will also be available.
	// The context is used to enforce timeouts on certain operations.
	Open(context.Context) error
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
	// leadership transfer is complete and return any error that occurred.
	Stepdown(wait bool) error
	// AddNonVoter adds a non-voting node to the cluster with timeout enforced by the context.
	AddNonVoter(ctx context.Context, id string, addr string) error
	// AddVoter adds a voting node to the cluster with timeout enforced by the context.
	AddVoter(ctx context.Context, id string, addr string) error
	// DemoteVoter demotes a voting node to a non-voting node with timeout enforced by the context.
	DemoteVoter(ctx context.Context, id string) error
	// RemoveServer removes a peer from the cluster with timeout enforced by the context.
	RemoveServer(ctx context.Context, id string, wait bool) error
	// DB returns a DB interface for use by the application.
	DB() meshdb.DB
	// Raft returns the Raft interface. Note that the returned value
	// may be nil if the store is not open.
	Raft() *raft.Raft
	// WireGuard returns the WireGuard interface. Note that the returned value
	// may be nil if the store is not open.
	WireGuard() wireguard.Interface
	// Plugins returns the plugin manager. Note that the returned value
	// may be nil if the store is not open.
	Plugins() plugins.Manager
}

// New creates a new store. You must call Open() on the returned store
// before it can become ready to use.
func New(opts *Options) (Store, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
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
		nodeID = determineNodeID(log, tlsConfig, opts)
	}
	sl, err := streamlayer.New(&streamlayer.Options{
		ListenAddress: opts.Raft.ListenAddress,
	})
	if err != nil {
		return nil, err
	}
	var taskGroup errgroup.Group
	taskGroup.SetLimit(1)
	st := &store{
		sl:          sl,
		opts:        opts,
		tlsConfig:   tlsConfig,
		nodeID:      raft.ServerID(nodeID),
		readyErr:    make(chan error, 2),
		nwTaskGroup: &taskGroup,
		log:         log.With(slog.String("node-id", string(nodeID))),
	}
	st.nw = net.New(st, &net.Options{
		InterfaceName:         opts.WireGuard.InterfaceName,
		ForceReplace:          opts.WireGuard.ForceInterfaceName,
		ListenPort:            opts.WireGuard.ListenPort,
		PersistentKeepAlive:   opts.WireGuard.PersistentKeepAlive,
		ForceTUN:              opts.WireGuard.ForceTUN,
		Modprobe:              opts.WireGuard.Modprobe,
		MTU:                   opts.WireGuard.MTU,
		RecordMetrics:         opts.WireGuard.RecordMetrics,
		RecordMetricsInterval: opts.WireGuard.RecordMetricsInterval,
		RaftPort:              sl.ListenPort(),
		GRPCPort:              opts.Mesh.GRPCPort,
		ZoneAwarenessID:       opts.Mesh.ZoneAwarenessID,
		DialOptions:           st.grpcCreds(context.Background()),
	})
	return st, nil
}

func determineNodeID(log *slog.Logger, tlsConfig *tls.Config, opts *Options) string {
	// Check if we are using mTLS.
	if tlsConfig != nil {
		if len(tlsConfig.Certificates) > 0 {
			clientCert := tlsConfig.Certificates[0]
			leaf, err := x509.ParseCertificate(clientCert.Certificate[0])
			if err != nil {
				log.Warn("unable to parse client certificate to determine node ID", slog.String("error", err.Error()))
			} else {
				nodeID := leaf.Subject.CommonName
				log.Info("using CN as node ID", slog.String("node-id", nodeID))
				return nodeID
			}
		}
	}
	// Check if we are using auth
	if opts.Auth != nil {
		if opts.Auth.Basic != nil && opts.Auth.Basic.Username != "" {
			log.Info("using basic auth username as node ID",
				slog.String("node-id", opts.Auth.Basic.Username))
			return opts.Auth.Basic.Username
		}
		if opts.Auth.LDAP != nil && opts.Auth.LDAP.Username != "" {
			log.Info("using LDAP username as node ID",
				slog.String("node-id", opts.Auth.LDAP.Username))
			return opts.Auth.LDAP.Username
		}
	}
	// Try to retrieve the system hostname
	hostname, err := os.Hostname()
	if err != nil {
		log.Warn("unable to retrieve system hostname, generating random UUID for node ID",
			slog.String("error", err.Error()))
		return uuid.NewString()
	}
	log.Info("using system hostname as node ID",
		slog.String("node-id", string(hostname)))
	return hostname
}

type store struct {
	sl   streamlayer.StreamLayer
	opts *Options
	log  *slog.Logger

	nodeID    raft.ServerID
	tlsConfig *tls.Config
	plugins   plugins.Manager

	readyErr       chan error
	firstBootstrap atomic.Bool

	raft             *raft.Raft
	lastAppliedIndex atomic.Uint64
	currentTerm      atomic.Uint64
	raftTransport    *raft.NetworkTransport
	raftSnapshots    raft.SnapshotStore
	logDB            LogStoreCloser
	stableDB         StableStoreCloser
	snapshotter      snapshots.Snapshotter

	observerChan                chan raft.Observation
	observer                    *raft.Observer
	observerClose, observerDone chan struct{}

	weakData, raftData *sql.DB
	dataMux            sync.RWMutex

	nw          meshnet.Manager
	nwTaskGroup *errgroup.Group

	open atomic.Bool

	// a flag set on test stores to indicate skipping certain operations
	testStore bool
}

// ID returns the node ID.
func (s *store) ID() string {
	return string(s.nodeID)
}

// IsOpen returns true if the store is open.
func (s *store) IsOpen() bool {
	return s.open.Load()
}

// DB returns a DB interface for use by the application.
func (s *store) DB() meshdb.DB {
	return &storeDB{s}
}

type storeDB struct {
	s *store
}

// Read returns a DB interface for use by the application.
func (s *storeDB) Read() meshdb.DBTX { return s.s.ReadDB() }

// Write returns a DB interface for use by the application.
func (s *storeDB) Write() meshdb.DBTX { return s.s.WriteDB() }

// WriteDB returns a DB interface for use by the application.
func (s *store) WriteDB() meshdb.DBTX {
	// Locks are taken during the application of log entries
	return s.raftData
}

// ReadDB returns a DB interface for use by the application.
func (s *store) ReadDB() meshdb.DBTX {
	return &roLockableDB{db: s.weakData, mu: &s.dataMux}
}

// Raft returns the Raft interface.
func (s *store) Raft() *raft.Raft { return s.raft }

// WireGuard returns the WireGuard interface. Note that the returned value
// may be nil if the store is not open.
func (s *store) WireGuard() wireguard.Interface { return s.nw.WireGuard() }

// Plugins returns the plugin manager. Note that the returned value
// may be nil if the store is not open.
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
// fails to become ready or nil.
func (s *store) ReadyError(ctx context.Context) <-chan error {
	if !s.firstBootstrap.Load() {
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

// IsLeader returns true if this node is the Raft leader.
func (s *store) IsLeader() bool {
	return s.State() == raft.Leader
}

// Leader returns the current Raft leader.
func (s *store) Leader() (raft.ServerID, error) {
	if s.raft == nil || !s.open.Load() {
		return "", ErrNotOpen
	}
	_, id := s.raft.LeaderWithID()
	if id == "" {
		return "", fmt.Errorf("no leader")
	}
	return id, nil
}

// LeaderAddr returns the address of the current leader.
func (s *store) LeaderAddr() (string, error) {
	if !s.open.Load() {
		return "", ErrNotOpen
	}
	addr, _ := s.raft.LeaderWithID()
	return string(addr), nil
}

// LeaderRPCAddr returns the gRPC address of the current leader.
func (s *store) LeaderRPCAddr(ctx context.Context) (string, error) {
	leader, err := s.Leader()
	if err != nil {
		return "", err
	}
	s.log.Debug("looking up rpc address for leader", slog.String("leader", string(leader)))
	state := state.New(s.DB())
	addr, err := state.GetNodePrivateRPCAddress(ctx, string(leader))
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}

// Stepdown forces this node to relinquish leadership to another node in
// the cluster. If wait is true then this method will block until the
// leadership transfer is complete and return any error that occurred.
func (s *store) Stepdown(wait bool) error {
	if !s.open.Load() {
		return ErrNotOpen
	}
	if !s.IsLeader() {
		return ErrNotLeader
	}
	f := s.raft.LeadershipTransfer()
	if !wait {
		return nil
	}
	return f.Error()
}

type LogStoreCloser interface {
	io.Closer
	raft.LogStore
}

type StableStoreCloser interface {
	io.Closer
	raft.StableStore
}
