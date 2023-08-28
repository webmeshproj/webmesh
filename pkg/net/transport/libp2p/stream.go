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
	"bufio"

	"github.com/libp2p/go-libp2p/core/network"
)

// Stream is a wrapper around a libp2p stream.
type Stream struct {
	buf *bufio.ReadWriter
	s   network.Stream
}

func (s *Stream) Read(p []byte) (int, error) { return s.buf.Read(p) }

func (s *Stream) Write(p []byte) (int, error) { return s.buf.Write(p) }

func (s *Stream) Close() error { return s.s.Close() }
