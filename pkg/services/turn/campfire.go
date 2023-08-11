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
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/pion/stun"
)

type campFireManager struct {
	net.PacketConn
	log    *slog.Logger
	peers  map[peer]net.Addr
	closec chan struct{}
	mu     sync.Mutex
}

type peer struct {
	ufrag       string
	pwd         string
	acceptUfrag string
	acceptPwd   string
	expires     int64
}

func newCampFireManager(pc net.PacketConn, log *slog.Logger) *campFireManager {
	cm := &campFireManager{
		PacketConn: pc,
		log:        log,
		peers:      make(map[peer]net.Addr),
		closec:     make(chan struct{}),
	}
	go cm.runPeerGC()
	return cm
}

func (s *campFireManager) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if n, addr, err = s.PacketConn.ReadFrom(p); err == nil && !stun.IsMessage(p) {
		data := p[:n]
		s.log.Debug("out-of-band inbound message", slog.Any("msg", string(data)))
		if isCampFireMessage(data) {
			s.log.Debug("handling inbound campfire message", slog.Any("msg", string(data)))
			var msg campfireMessage
			if derr := msg.decode(data); err != nil {
				s.log.Warn("failed to decode campfire message", slog.String("error", derr.Error()))
				return
			}
			s.handleCampFireMessage(&msg, addr)
		}
	}
	return
}

func (s *campFireManager) Close() error {
	close(s.closec)
	return s.PacketConn.Close()
}

func (s *campFireManager) handleCampFireMessage(msg *campfireMessage, saddr net.Addr) {
	s.log.Debug("handling campfire message", slog.Any("msg", msg))
	err := validateMessage(msg)
	if err != nil {
		s.log.Warn("invalid campfire message", slog.String("error", err.Error()))
		return
	}
	switch msg.Type {
	case campfireMessageAnnounce:
		s.handleAnnounce(msg, saddr)
	case campfireMessageOffer:
		s.handleOffer(msg, saddr)
	case campfireMessageAnswer:
		s.handleAnswer(msg, saddr)
	case campfireMessageICE:
		s.handleICE(msg, saddr)
	}
}

func (s *campFireManager) handleAnnounce(msg *campfireMessage, saddr net.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer := peer{
		ufrag:       msg.LUfrag,
		pwd:         msg.LPwd,
		acceptUfrag: msg.RUfrag,
		acceptPwd:   msg.RPwd,
		expires:     msg.expires,
	}
	s.peers[peer] = saddr
}

func (s *campFireManager) handleOffer(msg *campfireMessage, saddr net.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lpeer := peer{
		ufrag:       msg.LUfrag,
		pwd:         msg.LPwd,
		acceptUfrag: msg.RUfrag,
		acceptPwd:   msg.RPwd,
		expires:     msg.expires,
	}
	s.peers[lpeer] = saddr
	rpeer := peer{
		ufrag:       msg.RUfrag,
		pwd:         msg.RPwd,
		acceptUfrag: msg.LUfrag,
		acceptPwd:   msg.LPwd,
		expires:     msg.expires,
	}
	addr, ok := s.peers[rpeer]
	if !ok {
		s.log.Warn("no peer found for offer", slog.Any("peer", rpeer))
		return
	}
	s.log.Debug("sending offer to peer", slog.Any("peer", rpeer), slog.Any("addr", addr))
	encoded, err := msg.encode()
	if err != nil {
		s.log.Warn("failed to encode offer", slog.String("error", err.Error()))
		return
	}
	_, err = s.WriteTo(encoded, addr)
	if err != nil {
		s.log.Warn("failed to send offer", slog.String("error", err.Error()))
		return
	}
}

func (s *campFireManager) handleAnswer(msg *campfireMessage, saddr net.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lpeer := peer{
		ufrag:       msg.LUfrag,
		pwd:         msg.LPwd,
		acceptUfrag: msg.RUfrag,
		acceptPwd:   msg.RPwd,
		expires:     msg.expires,
	}
	s.peers[lpeer] = saddr
	rpeer := peer{
		ufrag:       msg.RUfrag,
		pwd:         msg.RPwd,
		acceptUfrag: msg.LUfrag,
		acceptPwd:   msg.LPwd,
		expires:     msg.expires,
	}
	addr, ok := s.peers[rpeer]
	if !ok {
		s.log.Warn("no peer found for answer", slog.Any("peer", rpeer))
		return
	}
	s.log.Debug("sending answer to peer", slog.Any("peer", rpeer), slog.Any("addr", addr))
	encoded, err := msg.encode()
	if err != nil {
		s.log.Warn("failed to encode answer", slog.String("error", err.Error()))
		return
	}
	_, err = s.WriteTo(encoded, addr)
	if err != nil {
		s.log.Warn("failed to send answer", slog.String("error", err.Error()))
		return
	}
}

func (s *campFireManager) handleICE(msg *campfireMessage, saddr net.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lpeer := peer{
		ufrag:       msg.LUfrag,
		pwd:         msg.LPwd,
		acceptUfrag: msg.RUfrag,
		acceptPwd:   msg.RPwd,
		expires:     msg.expires,
	}
	s.peers[lpeer] = saddr
	rpeer := peer{
		ufrag:       msg.RUfrag,
		pwd:         msg.RPwd,
		acceptUfrag: msg.LUfrag,
		acceptPwd:   msg.LPwd,
		expires:     msg.expires,
	}
	addr, ok := s.peers[rpeer]
	if !ok {
		s.log.Warn("no peer found for ICE candidate", slog.Any("peer", rpeer))
		return
	}
	s.log.Debug("sending ICE to peer", slog.Any("peer", rpeer), slog.Any("addr", addr))
	encoded, err := msg.encode()
	if err != nil {
		s.log.Warn("failed to encode ICE candidate", slog.String("error", err.Error()))
		return
	}
	_, err = s.WriteTo(encoded, addr)
	if err != nil {
		s.log.Warn("failed to send ICE candidate", slog.String("error", err.Error()))
		return
	}
}

func (s *campFireManager) runPeerGC() {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-s.closec:
			return
		case <-t.C:
			s.mu.Lock()
			now := time.Now().UTC().Truncate(time.Hour).Unix()
			for peer, addr := range s.peers {
				if now > peer.expires {
					delete(s.peers, peer)
					s.log.Debug("removed expired peer", slog.Any("peer", peer), slog.Any("addr", addr))
				}
			}
			s.mu.Unlock()
		}
	}

}

type messageType int

const (
	// campfireMessageAnnounce is a message type announcing presence
	campfireMessageAnnounce messageType = iota + 1
	// campfireMessageOffer is a message type for an offer
	campfireMessageOffer
	// campfireMessageAnswer is a message type for an answer
	campfireMessageAnswer
	// campfireMessageICE is a message type for an ICE candidate
	campfireMessageICE
)

type campfireMessage struct {
	LUfrag string
	LPwd   string
	RUfrag string
	RPwd   string
	Type   messageType
	Data   []byte

	expires int64
}

func (c *campfireMessage) encode() ([]byte, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return append([]byte("CAMPFIRE "), data...), nil
}

func (c *campfireMessage) decode(p []byte) error {
	data := bytes.TrimPrefix(p, []byte("CAMPFIRE "))
	err := json.NewDecoder(bytes.NewReader(data)).Decode(c)
	c.expires = time.Now().UTC().Truncate(time.Hour).Add(time.Hour).Unix()
	return err
}

func validateMessage(msg *campfireMessage) error {
	if msg.LUfrag == "" {
		return errors.New("missing lufrag")
	}
	if msg.LPwd == "" {
		return errors.New("missing lpwd")
	}
	if msg.RUfrag == "" {
		return errors.New("missing rufrag")
	}
	if msg.RPwd == "" {
		return errors.New("missing rpwd")
	}
	return nil
}

func isCampFireMessage(p []byte) bool {
	return bytes.HasPrefix(p, []byte("CAMPFIRE "))
}
