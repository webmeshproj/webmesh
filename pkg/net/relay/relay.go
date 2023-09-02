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

// Package relay holds low-level primitives for proxying streams to a WireGuard
// interface. The package can later be abstracted to support other proxying
// mechanisms.
package relay

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"

	"golang.org/x/sync/errgroup"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// Relay is a generic interface for proxying read-write streams between each other.
type Relay interface {
	// Relay proxies data to and from the given stream.
	Relay(ctx context.Context, from io.ReadWriteCloser) error
	// LocalAddr returns the local address of the relay.
	LocalAddr() netip.AddrPort
	// Closed returns a channel that is closed when the relay is closed.
	Closed() <-chan struct{}
	// Close closes the relay.
	Close() error
}

// DefaultUDPBuffer is the default buffer size to use for UDP relays.
const DefaultUDPBuffer = 1024 * 1024 * 4

// UDPOptions are generic options for a UDP relay.
type UDPOptions struct {
	// TargetPort is the port to proxy traffic to.
	TargetPort uint16
	// BufferSize is the size of the buffer to use for copying data.
	// If 0, DefaultUDPBuffer will be used.
	BufferSize int
}

// LocalUDP is a local UDP relay.
type LocalUDP struct {
	net.Conn
	addr    netip.AddrPort
	bufSize int
	closec  chan struct{}
}

// NewLocalUDP creates a new UDP relay listening on the given port
// and proxying traffic to the listener on the given target port.
func NewLocalUDP(opts UDPOptions) (Relay, error) {
	var laddr *net.UDPAddr
	c, err := net.DialUDP("udp", laddr, &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: int(opts.TargetPort),
	})
	if err != nil {
		return nil, err
	}
	return &LocalUDP{
		Conn:   c,
		addr:   c.LocalAddr().(*net.UDPAddr).AddrPort(),
		closec: make(chan struct{}),
		bufSize: func() int {
			if opts.BufferSize == 0 {
				return DefaultUDPBuffer
			}
			if opts.BufferSize > 0 {
				return opts.BufferSize
			}
			return DefaultUDPBuffer
		}(),
	}, nil
}

// Relay copies data from the given stream to and from the UDP connection.
// The stream will be closed when the relay is closed.
func (r *LocalUDP) Relay(ctx context.Context, from io.ReadWriteCloser) error {
	defer close(r.closec)
	log := context.LoggerFrom(ctx).With("relay", "wireguard", "local-addr", r.LocalAddr())
	defer log.Debug("Relay has finished")
	var errg errgroup.Group
	errg.Go(func() error {
		defer r.Conn.Close()
		defer log.Debug("Relay from local interface to stream stopped")
		log.Debug("Relay from local interface to stream started")
		_, err := io.CopyBuffer(from, r.Conn, make([]byte, r.bufSize))
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Error("Failed to relay from local interface to stream", slog.String("error", err.Error()))
			return fmt.Errorf("relay local interface to stream: %w", err)
		}
		return nil
	})
	errg.Go(func() error {
		defer from.Close()
		defer log.Debug("Relay from stream to local interface stopped")
		log.Debug("Relay from stream to local interface started")
		_, err := io.CopyBuffer(r.Conn, from, make([]byte, r.bufSize))
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("relay stream to local interface: %w", err)
		}
		return nil
	})
	return errg.Wait()
}

// LocalAddr returns the local address of the relay.
func (r *LocalUDP) LocalAddr() netip.AddrPort {
	return r.addr
}

// Closed returns a channel that is closed when the relay is closed.
func (r *LocalUDP) Closed() <-chan struct{} {
	return r.closec
}

// Close closes the relay.
func (r *LocalUDP) Close() error {
	return r.Conn.Close()
}
