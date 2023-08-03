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

// Package mesh contains the mesh store and related interfaces.
package mesh

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/google/uuid"
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"golang.org/x/sync/errgroup"

	"github.com/webmeshproj/webmesh/pkg/meshdb/state"
	"github.com/webmeshproj/webmesh/pkg/net"
	"github.com/webmeshproj/webmesh/pkg/plugins"
	"github.com/webmeshproj/webmesh/pkg/raft"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

var (
	// ErrNotOpen is returned when attempting to close a store that is not open.
	ErrNotOpen = fmt.Errorf("not open")
	// ErrOpen is returned when a store is already open.
	ErrOpen = fmt.Errorf("already open")
)

// Mesh is the connection to the Webmesh. It controls raft consensus, plugins,
// data storage, and WireGuard connections.
type Mesh interface {
	// ID returns the node ID.
	ID() string
	// Domain returns the domain of the mesh network.
	Domain() string
	// Open opens the connection to the mesh. This must be called before
	// other methods can be used.
	Open(ctx context.Context, features []v1.Feature) error
	// Close closes the connection to the mesh and shuts down the storage.
	Close() error
	// Leader returns the current Raft leader ID.
	Leader() (string, error)
	// LeaderRPCAddr returns the current Raft leader's gRPC address.
	LeaderRPCAddr(ctx context.Context) (string, error)
	// Storage returns a storage interface for use by the application.
	Storage() storage.Storage
	// Raft returns the Raft interface.
	Raft() raft.Raft
	// Network returns the Network manager.
	Network() net.Manager
	// Plugins returns the Plugin manager.
	Plugins() plugins.Manager
}

// New creates a new Mesh. You must call Open() on the returned mesh
// before it can be used.
func New(opts *Options) (Mesh, error) {
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
	st := &meshStore{
		opts:        opts,
		tlsConfig:   tlsConfig,
		nodeID:      nodeID,
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

type meshStore struct {
	opts *Options
	raft raft.Raft
	log  *slog.Logger

	nodeID    string
	tlsConfig *tls.Config
	plugins   plugins.Manager

	kvSubCancel context.CancelFunc

	nw          net.Manager
	nwTaskGroup *errgroup.Group
	meshDomain  string

	open atomic.Bool

	// a flag set on test stores to indicate skipping certain operations
	testStore bool
}

// ID returns the node ID.
func (s *meshStore) ID() string {
	return string(s.nodeID)
}

// Domain returns the domain of the mesh network.
func (s *meshStore) Domain() string {
	return s.meshDomain
}

// Storage returns a storage interface for use by the application.
func (s *meshStore) Storage() storage.Storage {
	return s.raft.Storage()
}

// Raft returns the Raft interface.
func (s *meshStore) Raft() raft.Raft {
	return s.raft
}

// Network returns the Network manager.
func (s *meshStore) Network() net.Manager {
	return s.nw
}

// Plugins returns the plugin manager. Note that the returned value
// may be nil if the store is not open.
func (s *meshStore) Plugins() plugins.Manager {
	return s.plugins
}

// Leader returns the current Raft leader.
func (s *meshStore) Leader() (string, error) {
	if s.raft == nil || !s.open.Load() {
		return "", ErrNotOpen
	}
	_, id := s.raft.Raft().LeaderWithID()
	if id == "" {
		return "", fmt.Errorf("no leader")
	}
	return string(id), nil
}

// LeaderRPCAddr returns the gRPC address of the current leader.
func (s *meshStore) LeaderRPCAddr(ctx context.Context) (string, error) {
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
