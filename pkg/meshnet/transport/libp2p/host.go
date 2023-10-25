//go:build !wasm

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

package libp2p

import (
	"fmt"
	"net"

	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	mnet "github.com/multiformats/go-multiaddr/net"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// Host is an interface that provides facilities for connecting to peers over libp2p.
type Host interface {
	// ID returns the peer ID of the host.
	ID() peer.ID
	// Host is the underlying libp2p host.
	Host() host.Host
	// RPCListener creates and returns a new net.Listener listening for RPC connections.
	// This should only ever be called once per host. The host will be closed when the
	// listener is closed.
	RPCListener() net.Listener
	// Close closes the host and its DHT.
	Close(ctx context.Context) error
}

// NewHost creates a new libp2p host with the given options.
func NewHost(ctx context.Context, opts HostOptions) (Host, error) {
	SetMaxSystemBuffers()
	if len(opts.LocalAddrs) > 0 {
		opts.Options = append(opts.Options, libp2p.ListenAddrs(opts.LocalAddrs...))
	}
	if opts.ConnectTimeout > 0 {
		opts.Options = append(opts.Options, libp2p.WithDialTimeout(opts.ConnectTimeout))
	}
	opts.Options = append(opts.Options, libp2p.FallbackDefaults)
	host, err := libp2p.New(opts.Options...)
	if err != nil {
		return nil, fmt.Errorf("new libp2p host: %w", err)
	}
	return wrapHost(host), nil
}

type libp2pHost struct {
	host      host.Host
	liscancel func()
}

// wrapHost wraps a libp2p host.
func wrapHost(host host.Host) Host {
	return &libp2pHost{host: host}
}

// ID returns the peer ID of the host.
func (h *libp2pHost) ID() peer.ID {
	return h.host.ID()
}

// Host returns the underlying libp2p host.
func (h *libp2pHost) Host() host.Host {
	return h.host
}

// RPCListener creates and returns a new net.Listener listening for RPC connections.
// This should only ever be called once per host.
func (h *libp2pHost) RPCListener() net.Listener {
	ch := make(chan net.Conn, 100)
	ctx, cancel := context.WithCancel(context.Background())
	h.host.SetStreamHandler(RPCProtocol, func(stream network.Stream) {
		ch <- &streamConn{stream}
	})
	h.liscancel = cancel
	return &hostRPCListener{
		h:       h,
		close:   cancel,
		closec:  ctx.Done(),
		acceptc: ch,
	}
}

// Close closes the host and shuts down all listeners.
func (h *libp2pHost) Close(ctx context.Context) error {
	if h.liscancel != nil {
		h.liscancel()
	}
	return h.host.Close()
}

type hostRPCListener struct {
	h       Host
	close   func()
	closec  <-chan struct{}
	acceptc chan net.Conn
}

// Accept waits for and returns the next connection to the listener.
func (h *hostRPCListener) Accept() (net.Conn, error) {
	select {
	case <-h.closec:
		return nil, fmt.Errorf("listener closed")
	case conn := <-h.acceptc:
		return conn, nil
	}
}

// Close closes the listener and underlying host.
func (h *hostRPCListener) Close() error {
	h.close()
	return h.h.Close(context.Background())
}

// Addr returns the listener's network address.
func (h *hostRPCListener) Addr() net.Addr {
	// Just return the first address.
	addrs := h.h.Host().Addrs()
	if len(addrs) == 0 {
		// This should never happen
		return nil
	}
	addr, _ := mnet.ToNetAddr(addrs[0])
	return addr
}

type streamConn struct {
	network.Stream
}

func (s *streamConn) LocalAddr() net.Addr {
	addr, _ := mnet.ToNetAddr(s.Stream.Conn().LocalMultiaddr())
	return addr
}

func (s *streamConn) RemoteAddr() net.Addr {
	addr, _ := mnet.ToNetAddr(s.Stream.Conn().RemoteMultiaddr())
	return addr
}
