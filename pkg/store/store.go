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
	"fmt"
	"os"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/hashicorp/raft"
	"golang.org/x/exp/slog"
	"golang.org/x/sync/errgroup"

	"github.com/webmeshproj/webmesh/pkg/meshdb/state"
	meshnet "github.com/webmeshproj/webmesh/pkg/net"
	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
	"github.com/webmeshproj/webmesh/pkg/plugins"
	meshraft "github.com/webmeshproj/webmesh/pkg/raft"
	"github.com/webmeshproj/webmesh/pkg/storage"
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
	// Domain returns the domain of the mesh network.
	Domain() string
	// Open opens the store. This must be called before the store can be used.
	// The Ready functions should be used to determine when the store is ready
	// to serve requests, after which the Wireguard interface will also be available.
	// The context is used to enforce timeouts on certain operations.
	Open(context.Context) error
	// IsOpen returns true if the store is open.
	IsOpen() bool
	// Close closes the store.
	Close() error
	// State returns the current Raft state.
	State() raft.RaftState
	// Leader returns the current Raft leader ID.
	Leader() (raft.ServerID, error)
	// LeaderAddr returns the current Raft leader's raft address.
	LeaderAddr() (string, error)
	// LeaderRPCAddr returns the current Raft leader's gRPC address.
	LeaderRPCAddr(ctx context.Context) (string, error)
	// Storage returns a storage interface for use by the application.
	Storage() storage.Storage
	// Raft returns the Raft interface. Note that the returned value
	// may be nil if the store is not open.
	Raft() meshraft.Raft
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
	var taskGroup errgroup.Group
	taskGroup.SetLimit(1)
	st := &store{
		opts:        opts,
		tlsConfig:   tlsConfig,
		nodeID:      raft.ServerID(nodeID),
		nwTaskGroup: &taskGroup,
		log:         log.With(slog.String("node-id", string(nodeID))),
		kvSubCancel: func() {},
	}
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
	log.Info("using system hostname as node ID", slog.String("node-id", string(hostname)))
	return hostname
}

type store struct {
	opts *Options
	raft meshraft.Raft
	log  *slog.Logger

	nodeID    raft.ServerID
	tlsConfig *tls.Config
	plugins   plugins.Manager

	kvSubCancel context.CancelFunc

	nw          meshnet.Manager
	nwTaskGroup *errgroup.Group
	meshDomain  string

	open atomic.Bool

	// a flag set on test stores to indicate skipping certain operations
	testStore bool
}

// ID returns the node ID.
func (s *store) ID() string {
	return string(s.nodeID)
}

// Domain returns the domain of the mesh network.
func (s *store) Domain() string {
	return s.meshDomain
}

// IsOpen returns true if the store is open.
func (s *store) IsOpen() bool {
	return s.open.Load()
}

// Storage returns a storage interface for use by the application.
func (s *store) Storage() storage.Storage {
	return s.raft.Storage()
}

// Raft returns the Raft interface.
func (s *store) Raft() meshraft.Raft { return s.raft }

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
	return s.raft.Raft().State()
}

// Leader returns the current Raft leader.
func (s *store) Leader() (raft.ServerID, error) {
	if s.raft == nil || !s.open.Load() {
		return "", ErrNotOpen
	}
	_, id := s.raft.Raft().LeaderWithID()
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
	addr, _ := s.raft.Raft().LeaderWithID()
	return string(addr), nil
}

// LeaderRPCAddr returns the gRPC address of the current leader.
func (s *store) LeaderRPCAddr(ctx context.Context) (string, error) {
	leader, err := s.Leader()
	if err != nil {
		return "", err
	}
	s.log.Debug("looking up rpc address for leader", slog.String("leader", string(leader)))
	state := state.New(s.Storage())
	addr, err := state.GetNodePrivateRPCAddress(ctx, string(leader))
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}
