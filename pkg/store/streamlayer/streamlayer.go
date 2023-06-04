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
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/raft"
)

// StreamLayer is the StreamLayer interface.
type StreamLayer interface {
	raft.StreamLayer
	// ListenPort returns the port the transport is listening on.
	ListenPort() int
}

// New creates a new stream layer with the given options.
func New(opts *Options) (StreamLayer, error) {
	ln, err := net.Listen("tcp", opts.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("listen %q: %w", opts.ListenAddress, err)
	}
	return &streamLayer{
		Listener: ln,
		Dialer:   &net.Dialer{},
	}, nil
}

type streamLayer struct {
	net.Listener
	*net.Dialer
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
