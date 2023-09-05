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

package embed

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/transport"
	"github.com/multiformats/go-multiaddr"

	"github.com/webmeshproj/webmesh/pkg/cmd/config"
	"github.com/webmeshproj/webmesh/pkg/context"
)

type Transport interface {
	io.Closer
	transport.Transport
}

// NewTransport returns a libp2p compatible transport backed by an embedded node.
func NewTransport(config *config.Config) (Transport, error) {
	return &libp2pTransport{
		config: config,
	}, nil
}

type libp2pTransport struct {
	config  *config.Config
	node    *node
	started atomic.Bool
	mu      sync.Mutex
}

// Dial dials a remote peer. It should try to reuse local listener
// addresses if possible, but it may choose not to.
func (l *libp2pTransport) Dial(ctx context.Context, raddr multiaddr.Multiaddr, p peer.ID) (transport.CapableConn, error) {
	return nil, errors.New("not implemented")
}

// CanDial returns true if this transport knows how to dial the given
// multiaddr.
//
// Returning true does not guarantee that dialing this multiaddr will
// succeed. This function should *only* be used to preemptively filter
// out addresses that we can't dial.
func (l *libp2pTransport) CanDial(addr multiaddr.Multiaddr) bool {
	return false
}

// Listen listens on the passed multiaddr.
func (l *libp2pTransport) Listen(laddr multiaddr.Multiaddr) (transport.Listener, error) {
	return nil, errors.New("not implemented")
}

// Protocol returns the set of protocols handled by this transport.
//
// See the Network interface for an explanation of how this is used.
func (l *libp2pTransport) Protocols() []int {
	return nil
}

// Proxy returns true if this is a proxy transport.
func (l *libp2pTransport) Proxy() bool {
	return true
}

// Close closes the transport.
func (l *libp2pTransport) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	defer l.started.Store(false)
	if l.node != nil {
		return l.node.Stop(context.Background())
	}
	return nil
}
