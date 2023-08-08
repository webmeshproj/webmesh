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

package turn

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net"

	"github.com/pion/stun"
)

type campFireManager struct {
	net.PacketConn
	log       *slog.Logger
	campfires map[string]*campFire
}

func newCampFireManager(pc net.PacketConn, log *slog.Logger) *campFireManager {
	return &campFireManager{
		PacketConn: pc,
		log:        log,
		campfires:  make(map[string]*campFire),
	}
}

func (s *campFireManager) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if n, err = s.PacketConn.WriteTo(p, addr); err == nil && !stun.IsMessage(p) {
		data := p[:n]
		s.log.Debug("out-of-band outbound message", slog.Any("msg", string(data)))
		if isCampFireMessage(data) {
			s.log.Debug("handling outbound campfire message", slog.Any("msg", string(data)))
			var msg campFireMessage
			if derr := msg.decode(data); err != nil {
				s.log.Warn("failed to decode campfire message", slog.String("error", derr.Error()))
				return
			}
			s.handleCampFireMessage(&msg)
		}
	}
	return
}

func (s *campFireManager) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if n, addr, err = s.PacketConn.ReadFrom(p); err == nil && !stun.IsMessage(p) {
		data := p[:n]
		s.log.Debug("out-of-band inbound message", slog.Any("msg", string(data)))
		if isCampFireMessage(data) {
			s.log.Debug("handling inbound campfire message", slog.Any("msg", string(data)))
			var msg campFireMessage
			if derr := msg.decode(data); err != nil {
				s.log.Warn("failed to decode campfire message", slog.String("error", derr.Error()))
				return
			}
			s.handleCampFireMessage(&msg)
		}
	}
	return
}

func (s *campFireManager) handleCampFireMessage(msg *campFireMessage) {
	s.log.Debug("handling campfire message", slog.Any("msg", msg))
	if msg.PSK == "" {
		s.log.Warn("campfire message missing psk")
		return
	}
}

type campFire struct{}

type campFireMessage struct {
	PSK string
}

// func (c *campFireMessage) encode() ([]byte, error) {
// 	var buf bytes.Buffer
// 	buf.WriteString("CAMPFIRE ")
// 	err := json.NewEncoder(&buf).Encode(c)
// 	return buf.Bytes(), err
// }

func (c *campFireMessage) decode(p []byte) error {
	data := bytes.TrimPrefix(p, []byte("CAMPFIRE "))
	err := json.NewDecoder(bytes.NewReader(data)).Decode(c)
	return err
}

func isCampFireMessage(p []byte) bool {
	return bytes.HasPrefix(p, []byte("CAMPFIRE "))
}
