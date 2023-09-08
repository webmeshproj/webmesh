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
	"context"
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
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/embed/security"
	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/util/logutil"
)

// ErrInvalidSecureTransport is returned when the transport is not used with a webmesh keypair and security transport.
var ErrInvalidSecureTransport = fmt.Errorf("transport must be used with a webmesh keypair and security transport")

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
			started: atomic.Bool{},
			opts:    opts,
			node:    nil,
			host:    host,
			key:     key,
			sec:     sec,
			mux:     mux,
			log:     logutil.NewLogger(opts.Config.Global.LogLevel).With("component", "webmesh-transport"),
			mu:      sync.Mutex{},
		}, nil
	}
}

// WebmeshTransport is the webmesh libp2p transport. It must be used with a webmesh keypair and security transport.
type WebmeshTransport struct {
	started atomic.Bool
	opts    Options
	node    mesh.Node
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
	return nil, nil
}

// CanDial returns true if this transport knows how to dial the given
// multiaddr.
//
// Returning true does not guarantee that dialing this multiaddr will
// succeed. This function should *only* be used to preemptively filter
// out addresses that we can't dial.
func (t *WebmeshTransport) CanDial(addr ma.Multiaddr) bool {
	return true
}

// Listen listens on the passed multiaddr.
func (t *WebmeshTransport) Listen(laddr ma.Multiaddr) (transport.Listener, error) {
	return nil, nil
}

// Resolve attempts to resolve the given multiaddr to a list of
// addresses.
func (t *WebmeshTransport) Resolve(ctx context.Context, maddr ma.Multiaddr) ([]ma.Multiaddr, error) {
	return nil, nil
}

// Protocol returns the set of protocols handled by this transport.
func (t *WebmeshTransport) Protocols() []int {
	return nil
}

// Proxy returns true if this is a proxy transport.
func (t *WebmeshTransport) Proxy() bool {
	return true
}

// Close closes the transport.
func (t *WebmeshTransport) Close() error {
	return nil
}
