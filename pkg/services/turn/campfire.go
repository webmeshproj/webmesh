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
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/proto"
)

// Now is a variable for mocking time in tests.
var Now = time.Now

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

// NewCampFireManager creates a new campfire manager.
func NewCampFireManager(pc net.PacketConn, log *slog.Logger) *campFireManager {
	cm := &campFireManager{
		PacketConn: pc,
		log:        log,
		peers:      make(map[peer]net.Addr),
		closec:     make(chan struct{}),
	}
	go cm.runPeerGC()
	return cm
}

// IsCampfireMessage returns true if the given packet is a campfire message.
func IsCampfireMessage(p []byte) bool {
	_, err := DecodeCampfireMessage(p)
	return err == nil
}

// EncodeCampfireMessage encodes a campfire message.
func EncodeCampfireMessage(msg *v1.CampfireMessage) ([]byte, error) {
	return proto.Marshal(msg)
}

// DecodeCampfireMessage decodes a campfire message.
func DecodeCampfireMessage(p []byte) (*v1.CampfireMessage, error) {
	var msg v1.CampfireMessage
	err := proto.Unmarshal(p, &msg)
	return &msg, err
}

// ValidateCampfireMessage validates a campfire message.
func ValidateCampfireMessage(msg *v1.CampfireMessage) error {
	if msg.Lufrag == "" {
		return errors.New("missing lufrag")
	}
	if msg.Lpwd == "" {
		return errors.New("missing lpwd")
	}
	if msg.Rufrag == "" {
		return errors.New("missing rufrag")
	}
	if msg.Rpwd == "" {
		return errors.New("missing rpwd")
	}
	if _, ok := v1.CampfireMessage_MessageType_name[int32(msg.Type)]; !ok {
		return errors.New("invalid message type")
	} else if msg.Type == v1.CampfireMessage_UNKNOWN {
		return errors.New("unknown message type")
	}
	return nil
}

func (s *campFireManager) ReadFrom(p []byte) (n int, addr net.Addr, rerr error) {
	if n, addr, rerr = s.PacketConn.ReadFrom(p); rerr == nil && IsCampfireMessage(p[:n]) {
		s.log.Debug("handling campfire message", "saddr", addr.String())
		msg, err := DecodeCampfireMessage(p[:n])
		if err != nil {
			s.log.Warn("failed to decode campfire message", slog.String("error", err.Error()))
			return
		}
		if err := ValidateCampfireMessage(msg); err != nil {
			s.log.Warn("invalid campfire message", slog.String("error", err.Error()))
			return
		}
		s.log.Debug("dispatching campfire message",
			slog.String("lufrag", msg.Lufrag),
			slog.String("lpwd", msg.Lpwd),
			slog.String("rufrag", msg.Rufrag),
			slog.String("rpwd", msg.Rpwd),
			slog.String("type", msg.Type.String()),
		)
		s.handleCampFireMessage(p[:n], msg, addr)
	}
	return
}

func (s *campFireManager) Close() error {
	close(s.closec)
	return s.PacketConn.Close()
}

func (s *campFireManager) handleCampFireMessage(pkt []byte, msg *v1.CampfireMessage, saddr net.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch msg.Type {
	case v1.CampfireMessage_ANNOUNCE:
		s.handleAnnounce(msg, saddr)
	case v1.CampfireMessage_OFFER:
		s.handleOffer(pkt, msg, saddr)
	case v1.CampfireMessage_ANSWER:
		s.handleAnswer(pkt, msg, saddr)
	case v1.CampfireMessage_CANDIDATE:
		s.handleICE(pkt, msg, saddr)
	}
}

func (s *campFireManager) handleAnnounce(msg *v1.CampfireMessage, saddr net.Addr) {
	peer := peer{
		ufrag:       msg.Lufrag,
		pwd:         msg.Lpwd,
		acceptUfrag: msg.Rufrag,
		acceptPwd:   msg.Rpwd,
		expires:     nextExpiry(),
	}
	s.peers[peer] = saddr
}

func (s *campFireManager) handleOffer(pkt []byte, msg *v1.CampfireMessage, saddr net.Addr) {
	lpeer := peer{
		ufrag:       msg.Lufrag,
		pwd:         msg.Lpwd,
		acceptUfrag: msg.Rufrag,
		acceptPwd:   msg.Rpwd,
		expires:     nextExpiry(),
	}
	s.peers[lpeer] = saddr
	rpeer := peer{
		ufrag:       msg.Rufrag,
		pwd:         msg.Rpwd,
		acceptUfrag: msg.Lufrag,
		acceptPwd:   msg.Lpwd,
		expires:     nextExpiry(),
	}
	addr, ok := s.peers[rpeer]
	if !ok {
		s.log.Warn("no peer found for offer", slog.Any("peer", rpeer))
		return
	}
	s.log.Debug("sending offer to peer", slog.Any("peer", rpeer), slog.Any("addr", addr))
	_, err := s.WriteTo(pkt, addr)
	if err != nil {
		s.log.Warn("failed to send offer", slog.String("error", err.Error()))
		return
	}
}

func (s *campFireManager) handleAnswer(pkt []byte, msg *v1.CampfireMessage, saddr net.Addr) {
	lpeer := peer{
		ufrag:       msg.Lufrag,
		pwd:         msg.Lpwd,
		acceptUfrag: msg.Rufrag,
		acceptPwd:   msg.Rpwd,
		expires:     nextExpiry(),
	}
	s.peers[lpeer] = saddr
	rpeer := peer{
		ufrag:       msg.Rufrag,
		pwd:         msg.Rpwd,
		acceptUfrag: msg.Lufrag,
		acceptPwd:   msg.Lpwd,
		expires:     nextExpiry(),
	}
	addr, ok := s.peers[rpeer]
	if !ok {
		s.log.Warn("no peer found for answer", slog.Any("peer", rpeer))
		return
	}
	s.log.Debug("sending answer to peer", slog.Any("peer", rpeer), slog.Any("addr", addr))
	_, err := s.WriteTo(pkt, addr)
	if err != nil {
		s.log.Warn("failed to send answer", slog.String("error", err.Error()))
		return
	}
}

func (s *campFireManager) handleICE(pkt []byte, msg *v1.CampfireMessage, saddr net.Addr) {
	lpeer := peer{
		ufrag:       msg.Lufrag,
		pwd:         msg.Lpwd,
		acceptUfrag: msg.Rufrag,
		acceptPwd:   msg.Rpwd,
		expires:     nextExpiry(),
	}
	s.peers[lpeer] = saddr
	rpeer := peer{
		ufrag:       msg.Rufrag,
		pwd:         msg.Rpwd,
		acceptUfrag: msg.Lufrag,
		acceptPwd:   msg.Lpwd,
		expires:     nextExpiry(),
	}
	addr, ok := s.peers[rpeer]
	if !ok {
		s.log.Warn("no peer found for ICE candidate", slog.Any("peer", rpeer))
		return
	}
	s.log.Debug("sending ICE to peer", slog.Any("peer", rpeer), slog.Any("addr", addr))
	_, err := s.WriteTo(pkt, addr)
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
			now := time.Now().Truncate(time.Hour).Unix()
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

func nextExpiry() int64 {
	return Now().Truncate(time.Hour).Add(time.Hour).Unix()
}
