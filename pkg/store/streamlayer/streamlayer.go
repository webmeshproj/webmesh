/*
Copyright 2023.

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

// Package streamlayer contains the Raft stream layer implementation.
package streamlayer

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/raft"
)

// StreamLayer is the StreamLayer interface.
type StreamLayer interface {
	raft.StreamLayer

	// Insecure returns true if the transport is insecure.
	Insecure() bool
	// TLSConfig returns the TLS config, if any.
	TLSConfig() *tls.Config
	// ListenPort returns the port the transport is listening on.
	ListenPort() int
}

// New creates a new stream layer with the given options.
func New(opts *Options) (StreamLayer, error) {
	if opts.Insecure {
		return NewInsecure(opts.ListenAddress)
	}
	tlsConfig, err := opts.TLSConfig()
	if err != nil {
		return nil, fmt.Errorf("generate tls config: %w", err)
	}
	ln, err := tls.Listen("tcp", opts.ListenAddress, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("listen %q: %w", opts.ListenAddress, err)
	}
	return &streamLayer{
		Listener: ln,
		Dialer: &tls.Dialer{
			Config: tlsConfig,
		},
	}, nil
}

type streamLayer struct {
	net.Listener
	*tls.Dialer
}

func (t *streamLayer) Insecure() bool { return false }

func (t *streamLayer) TLSConfig() *tls.Config {
	return t.Dialer.Config
}

func (t *streamLayer) ListenPort() int {
	return t.Listener.Addr().(*net.TCPAddr).Port
}

// Dial is used to create a new outgoing connection
func (t *streamLayer) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return t.DialContext(ctx, "tcp", string(address))
}

// NewInsecure creates a new insecure transport. This is used for
// testing only.
func NewInsecure(listenAddr string) (StreamLayer, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen %q: %w", listenAddr, err)
	}
	return &insecureStreamLayer{
		Listener: ln,
		Dialer:   &net.Dialer{},
	}, nil
}

type insecureStreamLayer struct {
	net.Listener
	*net.Dialer
}

func (t *insecureStreamLayer) Insecure() bool { return true }

func (t *insecureStreamLayer) TLSConfig() *tls.Config {
	return nil
}

func (t *insecureStreamLayer) ListenPort() int {
	return t.Listener.Addr().(*net.TCPAddr).Port
}

// Dial is used to create a new outgoing connection
func (t *insecureStreamLayer) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return t.DialContext(ctx, "tcp", string(address))
}
