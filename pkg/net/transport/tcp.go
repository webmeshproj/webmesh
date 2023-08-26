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

package transport

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// NewTCPTransport creates a new TCP transport listening on the given address.
func NewTCPTransport(addr string) (Transport, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	return &TCPTransport{
		Listener: ln,
		Dialer:   &net.Dialer{},
	}, nil
}

// TCPTransport is a transport that uses raw TCP.
type TCPTransport struct {
	net.Listener
	*net.Dialer
}

func (t *TCPTransport) AddrPort() netip.AddrPort {
	return t.Addr().(*net.TCPAddr).AddrPort()
}

func (t *TCPTransport) Dial(ctx context.Context, address string) (net.Conn, error) {
	return t.DialContext(ctx, "tcp", address)
}
