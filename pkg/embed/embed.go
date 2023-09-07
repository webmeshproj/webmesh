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

// Package embed provides a simplified way to run a webmesh node in-process.
package embed

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/cmd/config"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/net/transport"
	"github.com/webmeshproj/webmesh/pkg/net/transport/libp2p"
	"github.com/webmeshproj/webmesh/pkg/raft"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/services/meshdns"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/util/logutil"
)

// Node is an embedded webmesh node.
type Node interface {
	transport.Dialer
	transport.NodeDialer
	transport.LeaderDialer

	// Start starts the node.
	Start(ctx context.Context) error
	// Stop stops the node.
	Stop(ctx context.Context) error
	// Errors returns a channel of errors that occur during the lifetime of the node.
	// At the moment, any error is fatal and will cause the node to stop.
	Errors() <-chan error
	// Mesh returns the underlying mesh instance.
	Mesh() mesh.Mesh
	// Raft is the underlying Raft instance.
	Raft() raft.Raft
	// Storage is the underlying storage instance.
	Storage() storage.MeshStorage
	// Services returns the underlying services instance if it is running.
	Services() *services.Server
	// MeshDNS returns the underlying MeshDNS instance if it is running.
	MeshDNS() *meshdns.Server
	// AddressV4 returns the IPv4 address of the node.
	AddressV4() netip.Prefix
	// AddressV6 returns the IPv6 address of the node.
	AddressV6() netip.Prefix
}

// NewNode creates a new embedded webmesh node.
func NewNode(ctx context.Context, config *config.Config) (Node, error) {
	if config.Mesh.DisableIPv4 && config.Mesh.DisableIPv6 {
		return nil, fmt.Errorf("cannot disable both IPv4 and IPv6")
	}
	log := logutil.SetupLogging(config.Global.LogLevel)
	if config.Global.LogLevel == "" || config.Global.LogLevel == "silent" {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
		ctx = context.WithLogger(ctx, log)
	}
	// Create a new mesh connection
	meshConfig, err := config.NewMeshConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create mesh config: %w", err)
	}
	meshConn := mesh.NewWithLogger(log, meshConfig)
	// Create a new raft node
	raftNode, err := config.NewRaftNode(ctx, meshConn)
	if err != nil {
		return nil, fmt.Errorf("failed to create raft node: %w", err)
	}
	startOpts, err := config.NewRaftStartOptions(meshConn)
	if err != nil {
		return nil, fmt.Errorf("failed to create raft start options: %w", err)
	}
	connectOpts, err := config.NewConnectOptions(ctx, meshConn, raftNode, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create connect options: %w", err)
	}
	return &node{
		conf:          config,
		log:           log,
		mesh:          meshConn,
		raft:          raftNode,
		storage:       raftNode.Storage(),
		raftStartOpts: startOpts,
		connectOpts:   connectOpts,
		errs:          make(chan error, 1),
	}, nil
}

// NewNodeWithKey returns a new node using the given key.
func NewNodeWithKey(ctx context.Context, config *config.Config, key crypto.Key) (Node, error) {
	if config.Mesh.DisableIPv4 && config.Mesh.DisableIPv6 {
		return nil, fmt.Errorf("cannot disable both IPv4 and IPv6")
	}
	log := logutil.SetupLogging(config.Global.LogLevel)
	if config.Global.LogLevel == "" || config.Global.LogLevel == "silent" {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
		ctx = context.WithLogger(ctx, log)
	}
	// Create a new mesh connection
	meshConfig, err := config.NewMeshConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create mesh config: %w", err)
	}
	meshConfig.Key = key
	meshConn := mesh.NewWithLogger(log, meshConfig)
	// Create a new raft node
	raftNode, err := config.NewRaftNode(ctx, meshConn)
	if err != nil {
		return nil, fmt.Errorf("failed to create raft node: %w", err)
	}
	startOpts, err := config.NewRaftStartOptions(meshConn)
	if err != nil {
		return nil, fmt.Errorf("failed to create raft start options: %w", err)
	}
	connectOpts, err := config.NewConnectOptions(ctx, meshConn, raftNode, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create connect options: %w", err)
	}
	return &node{
		conf:          config,
		log:           log,
		mesh:          meshConn,
		raft:          raftNode,
		storage:       raftNode.Storage(),
		raftStartOpts: startOpts,
		connectOpts:   connectOpts,
		errs:          make(chan error, 1),
	}, nil
}

// NewNodeWithKeyAndHost returns a new node using the given key and pre-created libp2p host.
// This is mostly intended for use with transports.
func NewNodeWithKeyAndHost(ctx context.Context, config *config.Config, key crypto.Key, host libp2p.Host) (Node, error) {
	if config.Mesh.DisableIPv4 && config.Mesh.DisableIPv6 {
		return nil, fmt.Errorf("cannot disable both IPv4 and IPv6")
	}
	log := logutil.SetupLogging(config.Global.LogLevel)
	if config.Global.LogLevel == "" || config.Global.LogLevel == "silent" {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
		ctx = context.WithLogger(ctx, log)
	}
	// Create a new mesh connection
	meshConfig, err := config.NewMeshConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create mesh config: %w", err)
	}
	meshConfig.Key = key
	meshConn := mesh.NewWithLogger(log, meshConfig)
	// Create a new raft node
	raftNode, err := config.NewRaftNode(ctx, meshConn)
	if err != nil {
		return nil, fmt.Errorf("failed to create raft node: %w", err)
	}
	startOpts, err := config.NewRaftStartOptions(meshConn)
	if err != nil {
		return nil, fmt.Errorf("failed to create raft start options: %w", err)
	}
	connectOpts, err := config.NewConnectOptions(ctx, meshConn, raftNode, host)
	if err != nil {
		return nil, fmt.Errorf("failed to create connect options: %w", err)
	}
	return &node{
		conf:          config,
		log:           log,
		mesh:          meshConn,
		raft:          raftNode,
		storage:       raftNode.Storage(),
		raftStartOpts: startOpts,
		connectOpts:   connectOpts,
		errs:          make(chan error, 1),
	}, nil
}

type node struct {
	conf          *config.Config
	log           *slog.Logger
	mesh          mesh.Mesh
	raft          raft.Raft
	storage       storage.MeshStorage
	services      *services.Server
	meshdns       *meshdns.Server
	raftStartOpts raft.StartOptions
	connectOpts   mesh.ConnectOptions
	errs          chan error
	mu            sync.Mutex
}

func (n *node) Mesh() mesh.Mesh {
	return n.mesh
}

func (n *node) Raft() raft.Raft {
	return n.raft
}

func (n *node) Storage() storage.MeshStorage {
	return n.storage
}

func (n *node) Services() *services.Server {
	return n.services
}

func (n *node) MeshDNS() *meshdns.Server {
	return n.meshdns
}

func (n *node) Errors() <-chan error {
	return n.errs
}

func (n *node) AddressV4() netip.Prefix {
	return n.mesh.Network().WireGuard().AddressV4()
}

func (n *node) AddressV6() netip.Prefix {
	return n.mesh.Network().WireGuard().AddressV6()
}

func (n *node) Start(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	log := n.log
	ctx = context.WithLogger(ctx, log)
	// Start the raft node
	err := n.Raft().Start(ctx, n.raftStartOpts)
	if err != nil {
		return fmt.Errorf("failed to start raft node: %w", err)
	}
	// Connect to the mesh
	err = n.Mesh().Connect(ctx, n.connectOpts)
	if err != nil {
		defer func() {
			err := n.Raft().Stop(context.Background())
			if err != nil {
				log.Error("failed to shutdown raft node", slog.String("error", err.Error()))
			}
		}()
		return fmt.Errorf("failed to open mesh connection: %w", err)
	}

	// If anything goes wrong at this point, make sure we close down cleanly.
	handleErr := func(cause error) error {
		if err := n.Mesh().Close(); err != nil {
			log.Error("failed to shutdown mesh", slog.String("error", err.Error()))
		}
		return fmt.Errorf("failed to start mesh node: %w", cause)
	}

	log.Info("Connected to mesh, starting services")

	// Start the mesh services
	srvOpts, err := n.conf.NewServiceOptions(ctx, n.Mesh())
	if err != nil {
		return handleErr(fmt.Errorf("failed to create service options: %w", err))
	}
	n.services, err = services.NewServer(ctx, srvOpts)
	if err != nil {
		return handleErr(fmt.Errorf("failed to create gRPC server: %w", err))
	}
	if !n.conf.Services.API.Disabled {
		err = n.conf.RegisterAPIs(ctx, n.Mesh(), n.services)
		if err != nil {
			return handleErr(fmt.Errorf("failed to register APIs: %w", err))
		}
	}
	select {
	case <-n.Mesh().Ready():
	case <-ctx.Done():
		return fmt.Errorf("failed to start mesh node: %w", ctx.Err())
	}

	log.Info("Webmesh is ready")
	go func() {
		if err := n.services.ListenAndServe(); err != nil {
			n.errs <- handleErr(fmt.Errorf("failed to start gRPC server: %w", err))
		}
	}()
	return nil
}

func (s *node) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return s.mesh.Dial(ctx, network, address)
}

func (s *node) DialLeader(ctx context.Context) (*grpc.ClientConn, error) {
	return s.mesh.DialLeader(ctx)
}

func (s *node) DialNode(ctx context.Context, nodeID string) (*grpc.ClientConn, error) {
	return s.mesh.DialNode(ctx, nodeID)
}

func (n *node) Stop(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	// Shutdown the mesh connection last
	defer func() {
		n.log.Info("Shutting down mesh connection")
		if err := n.Mesh().Close(); err != nil {
			n.log.Error("failed to shutdown mesh connection", slog.String("error", err.Error()))
		}
	}()
	// Stop the gRPC server
	n.log.Info("Shutting down mesh services")
	if n.services != nil {
		n.services.Shutdown(ctx)
	}
	return nil
}
