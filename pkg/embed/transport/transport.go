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

// Package transport defines the libp2p webmesh transport.
package transport

import (
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/sec"
	"github.com/libp2p/go-libp2p/core/transport"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/cmd/config"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/embed/protocol"
	"github.com/webmeshproj/webmesh/pkg/embed/security"
	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/util/logutil"
)

// ErrInvalidSecureTransport is returned when the transport is not used with a webmesh keypair and security transport.
var ErrInvalidSecureTransport = fmt.Errorf("transport must be used with a webmesh keypair and security transport")

// ErrNotStarted is returned when the transport is not started.
var ErrNotStarted = fmt.Errorf("transport is not started")

// Transport is the webmesh transport.
type Transport interface {
	// Closer for the underlying transport that shuts down the webmesh node.
	io.Closer
	// Transport is the underlying libp2p Transport.
	transport.Transport
	// Resolver is a resolver that uses the mesh storage to lookup peers.
	transport.Resolver
}

// TransportBuilder is the signature of a function that builds a webmesh transport.
type TransportBuilder func(upgrader transport.Upgrader, host host.Host, st sec.SecureTransport, mux network.Multiplexer, privKey pcrypto.PrivKey) (Transport, error)

// Options are the options for the webmesh transport.
type Options struct {
	// Config is the webmesh config.
	Config *config.Config
	// StartTimeout is the timeout for starting the webmesh node.
	StartTimeout time.Duration
	// StopTimeout is the timeout for stopping the webmesh node.
	StopTimeout time.Duration
}

// New returns a new webmesh transport builder.
func New(opts Options) TransportBuilder {
	if opts.Config == nil {
		panic("config is required")
	}
	return func(upgrader transport.Upgrader, host host.Host, st sec.SecureTransport, mux network.Multiplexer, privKey pcrypto.PrivKey) (Transport, error) {
		sec, ok := st.(*security.SecureTransport)
		if !ok {
			return nil, ErrInvalidSecureTransport
		}
		key, ok := privKey.(crypto.PrivateKey)
		if !ok {
			return nil, ErrInvalidSecureTransport
		}
		return &WebmeshTransport{
			opts: opts,
			node: nil,
			host: host,
			key:  key,
			sec:  sec,
			mux:  mux,
			log:  logutil.NewLogger(opts.Config.Global.LogLevel).With("component", "webmesh-transport"),
		}, nil
	}
}

// WebmeshTransport is the webmesh libp2p transport. It must be used with a webmesh keypair and security transport.
type WebmeshTransport struct {
	started atomic.Bool
	opts    Options
	node    mesh.Node
	svcs    *services.Server
	host    host.Host
	key     crypto.PrivateKey
	sec     *security.SecureTransport
	mux     network.Multiplexer
	log     *slog.Logger
	mu      sync.Mutex
}

// Dial dials a remote peer. It should try to reuse local listener
// addresses if possible, but it may choose not to.
func (t *WebmeshTransport) Dial(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (transport.CapableConn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.started.Load() {
		return nil, ErrNotStarted
	}
	// TODO: Implement
	return nil, nil
}

// CanDial returns true if this transport knows how to dial the given
// multiaddr.
//
// Returning true does not guarantee that dialing this multiaddr will
// succeed. This function should *only* be used to preemptively filter
// out addresses that we can't dial.
func (t *WebmeshTransport) CanDial(addr ma.Multiaddr) bool {
	// TODO: Implement
	return t.started.Load()
}

// Listen listens on the passed multiaddr.
func (t *WebmeshTransport) Listen(laddr ma.Multiaddr) (transport.Listener, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.started.Load() {
		node, err := t.startNode()
		if err != nil {
			return nil, fmt.Errorf("failed to start node: %w", err)
		}
		t.node = node
		t.sec.SetInterface(node.Network().WireGuard())
		t.started.Store(true)
	}
	// TODO: Implement
	return nil, nil
}

// Resolve attempts to resolve the given multiaddr to a list of
// addresses.
func (t *WebmeshTransport) Resolve(ctx context.Context, maddr ma.Multiaddr) ([]ma.Multiaddr, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.started.Load() {
		return nil, ErrNotStarted
	}
	// TODO: Implement
	return nil, nil
}

// Protocol returns the set of protocols handled by this transport.
func (t *WebmeshTransport) Protocols() []int {
	return []int{protocol.Code}
}

// Proxy returns true if this is a proxy transport.
func (t *WebmeshTransport) Proxy() bool {
	return true
}

// Close closes the transport.
func (t *WebmeshTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.started.Load() {
		return ErrNotStarted
	}
	defer t.started.Store(false)
	ctx := context.Background()
	if t.opts.StopTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.opts.StopTimeout)
		defer cancel()
	}
	if t.svcs != nil {
		defer t.svcs.Shutdown(ctx)
	}
	return t.node.Close(ctx)
}

func (t *WebmeshTransport) startNode() (mesh.Node, error) {
	ctx := context.WithLogger(context.Background(), t.log)
	if t.opts.StartTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.opts.StartTimeout)
		defer cancel()
	}
	conf := t.opts.Config.ShallowCopy()
	conf.Mesh.NodeID = t.key.ID().String()
	err := conf.Validate()
	if err != nil {
		return nil, fmt.Errorf("failed to validate config: %w", err)
	}

	// Build out everything we need for a new node
	meshConfig, err := conf.NewMeshConfig(ctx, t.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create mesh config: %w", err)
	}
	node := mesh.NewWithLogger(t.log, meshConfig)
	startOpts, err := conf.NewRaftStartOptions(node)
	if err != nil {
		return nil, fmt.Errorf("failed to create raft start options: %w", err)
	}
	raft, err := conf.NewRaftNode(ctx, node)
	if err != nil {
		return nil, fmt.Errorf("failed to create raft node: %w", err)
	}
	connectOpts, err := conf.NewConnectOptions(ctx, node, raft, t.host)
	if err != nil {
		return nil, fmt.Errorf("failed to create connect options: %w", err)
	}

	// Define cleanup handlers
	var cleanFuncs []func() error
	handleErr := func(cause error) error {
		for _, clean := range cleanFuncs {
			if err := clean(); err != nil {
				t.log.Warn("failed to clean up", "error", err.Error())
			}
		}
		return cause
	}

	t.log.Info("Starting webmesh node")
	err = raft.Start(ctx, startOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to start raft node: %w", err)
	}
	cleanFuncs = append(cleanFuncs, func() error {
		return raft.Stop(ctx)
	})
	err = node.Connect(ctx, connectOpts)
	if err != nil {
		return nil, handleErr(fmt.Errorf("failed to connect to mesh: %w", err))
	}
	cleanFuncs = append(cleanFuncs, func() error {
		return node.Close(ctx)
	})

	// Start any mesh services
	srvOpts, err := conf.NewServiceOptions(ctx, node)
	if err != nil {
		return nil, handleErr(fmt.Errorf("failed to create service options: %w", err))
	}
	t.svcs, err = services.NewServer(ctx, srvOpts)
	if err != nil {
		return nil, handleErr(fmt.Errorf("failed to create mesh services: %w", err))
	}
	if !conf.Services.API.Disabled {
		err = conf.RegisterAPIs(ctx, node, t.svcs)
		if err != nil {
			return nil, handleErr(fmt.Errorf("failed to register APIs: %w", err))
		}
	}
	errs := make(chan error, 1)
	go func() {
		t.log.Info("Starting webmesh services")
		if err := t.svcs.ListenAndServe(); err != nil {
			errs <- fmt.Errorf("start mesh services %w", err)
		}
	}()

	// Wait for the node to be ready
	t.log.Info("Waiting for webmesh node to be ready")
	select {
	case <-node.Ready():
	case err := <-errs:
		return nil, handleErr(err)
	case <-ctx.Done():
		return nil, handleErr(fmt.Errorf("failed to start mesh node: %w", ctx.Err()))
	}
	t.log.Info("Webmesh node is ready")
	return node, nil
}
