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

	"github.com/libp2p/go-libp2p/core/host"
	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/config"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/logging"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport"
	"github.com/webmeshproj/webmesh/pkg/meshnode"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/services/meshdns"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
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
	Mesh() meshnode.Node
	// Storage is the underlying storage instance.
	Storage() storage.Provider
	// Services returns the underlying services instance if it is running.
	Services() *services.Server
	// MeshDNS returns the underlying MeshDNS instance if it is running.
	MeshDNS() *meshdns.Server
	// AddressV4 returns the IPv4 address of the node.
	AddressV4() netip.Prefix
	// AddressV6 returns the IPv6 address of the node.
	AddressV6() netip.Prefix
}

// Options are the options for creating a new embedded webmesh node.
type Options struct {
	// Config is the configuration for the node.
	Config *config.Config
	// Key is the key for the node.
	Key crypto.PrivateKey
	// Host is the libp2p host for the node.
	Host host.Host
}

// NewNode creates a new embedded webmesh node.
func NewNode(ctx context.Context, opts Options) (Node, error) {
	config := opts.Config
	if config.Mesh.DisableIPv4 && config.Mesh.DisableIPv6 {
		return nil, fmt.Errorf("cannot disable both IPv4 and IPv6")
	}
	log := logging.SetupLogging(config.Global.LogLevel, config.Global.LogFormat)
	if config.Global.LogLevel == "" || config.Global.LogLevel == "silent" {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
		ctx = context.WithLogger(ctx, log)
	}
	// Create a new mesh connection
	meshConfig, err := config.NewMeshConfig(ctx, opts.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create mesh config: %w", err)
	}
	meshConn := meshnode.NewWithLogger(log, meshConfig)
	// Create a storage provider
	storageProvider, err := config.NewStorageProvider(ctx, meshConn, config.Bootstrap.Force)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage provider: %w", err)
	}
	return &node{
		opts:    opts,
		conf:    config,
		log:     log,
		mesh:    meshConn,
		storage: storageProvider,
		errs:    make(chan error, 1),
	}, nil
}

type node struct {
	opts     Options
	conf     *config.Config
	log      *slog.Logger
	mesh     meshnode.Node
	storage  storage.Provider
	services *services.Server
	meshdns  *meshdns.Server
	errs     chan error
	mu       sync.Mutex
}

func (n *node) Mesh() meshnode.Node {
	return n.mesh
}

func (n *node) Storage() storage.Provider {
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
	connectOpts, err := n.conf.NewConnectOptions(ctx, n.Mesh(), n.Storage(), n.opts.Host)
	if err != nil {
		return fmt.Errorf("failed to create connect options: %w", err)
	}
	// Start the raft node
	err = n.Storage().Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start raft node: %w", err)
	}
	// Connect to the mesh
	err = n.Mesh().Connect(ctx, connectOpts)
	if err != nil {
		defer func() {
			err := n.Storage().Close()
			if err != nil {
				log.Error("failed to shutdown raft node", slog.String("error", err.Error()))
			}
		}()
		return fmt.Errorf("failed to open mesh connection: %w", err)
	}

	// If anything goes wrong at this point, make sure we close down cleanly.
	handleErr := func(cause error) error {
		if err := n.Mesh().Close(ctx); err != nil {
			log.Error("failed to shutdown mesh", slog.String("error", err.Error()))
		}
		return fmt.Errorf("failed to start mesh node: %w", cause)
	}

	log.Info("Connected to mesh, starting services")

	// Start the mesh services
	srvOpts, err := n.conf.Services.NewServiceOptions(ctx, n.Mesh())
	if err != nil {
		return handleErr(fmt.Errorf("failed to create service options: %w", err))
	}
	n.services, err = services.NewServer(ctx, srvOpts)
	if err != nil {
		return handleErr(fmt.Errorf("failed to create webmesh server: %w", err))
	}
	isStorageMember := n.conf.IsStorageMember()
	features := n.conf.Services.NewFeatureSet(n.conf.Services.API.ListenPort(), n.conf.Storage.ListenPort(), isStorageMember)
	if !n.conf.Services.API.Disabled {
		err = n.conf.Services.RegisterAPIs(ctx, n.Mesh(), n.services, features, isStorageMember)
		if err != nil {
			return handleErr(fmt.Errorf("failed to register APIs: %w", err))
		}
	}
	select {
	case <-n.Mesh().Ready():
	case <-ctx.Done():
		return handleErr(fmt.Errorf("failed to start webmesh node: %w", ctx.Err()))
	}

	log.Info("Webmesh is ready")
	go func() {
		if err := n.services.ListenAndServe(); err != nil {
			n.errs <- fmt.Errorf("failed to start webmesh services: %w", err)
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

func (s *node) DialNode(ctx context.Context, nodeID types.NodeID) (*grpc.ClientConn, error) {
	return s.mesh.DialNode(ctx, nodeID)
}

func (n *node) Stop(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	// Shutdown the mesh connection last
	defer func() {
		n.log.Info("Shutting down mesh connection")
		if err := n.Mesh().Close(ctx); err != nil {
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
