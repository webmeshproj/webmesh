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

package wgtransport

import (
	"net"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"golang.org/x/net/ipv6"
)

// Ensure we implement the interface
var _ network.MuxedStream = (*PacketStream)(nil)

// PacketStream is a multiplexed stream.
type PacketStream struct {
	*ipv6.PacketConn
	group *net.UDPAddr
}

// Read reads data from the stream.
func (s *PacketStream) Read(b []byte) (int, error) {
	n, _, _, err := s.PacketConn.ReadFrom(b)
	return n, err
}

// Write writes data to the stream.
func (s *PacketStream) Write(b []byte) (int, error) {
	wcm := ipv6.ControlMessage{TrafficClass: 0xe0, HopLimit: 1}
	return s.PacketConn.WriteTo(b, &wcm, s.group)
}

// CloseRead closes the stream for reading but leaves it open for
// writing.
//
// When CloseRead is called, all in-progress Read calls are interrupted with a non-EOF error and
// no further calls to Read will succeed.
//
// The handling of new incoming data on the stream after calling this function is implementation defined.
//
// CloseRead does not free the stream, users must still call Close or
// Reset.
func (s *PacketStream) CloseRead() error {
	// A bit of a hack but we just make all future reads fail.
	// The caller could technically remove this deadline but that's
	// not our problem.
	return s.PacketConn.SetReadDeadline(time.Now())
}

// CloseWrite closes the stream for writing but leaves it open for
// reading.
//
// CloseWrite does not free the stream, users must still call Close or
// Reset.
func (s *PacketStream) CloseWrite() error {
	// A bit of a hack but we just make all future writes fail.
	// The caller could technically remove this deadline but that's
	// not our problem.
	return s.PacketConn.SetWriteDeadline(time.Now())
}

// Reset closes both ends of the stream. Use this to tell the remote
// side to hang up and go away.
func (s *PacketStream) Reset() error {
	return s.PacketConn.Close()
}
