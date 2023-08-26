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

// Package transport provides a simple interface for sending and receiving raft
// messages between nodes.
package transport

import (
	"context"
	"net"
	"net/netip"
)

// Transport is the interface for sending and receiving messages between nodes.
type Transport interface {
	net.Listener

	// Dial is used to create a new outgoing connection
	Dial(ctx context.Context, address string) (net.Conn, error)

	// AddrPort returns the address and port the transport is listening on.
	AddrPort() netip.AddrPort
}
