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
	"log/slog"
	"net"
	"sync"
	"time"
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

func (s *campFireManager) ReadFrom(p []byte) (n int, addr net.Addr, rerr error) {
	if n, addr, rerr = s.PacketConn.ReadFrom(p); rerr == nil && IsCampfireMessage(p) {
		s.log.Debug("handling campfire message", "saddr", addr.String())
		msg, err := DecodeCampfireMessage(p[:n])
		if err != nil {
			s.log.Warn("failed to decode campfire message", slog.String("error", err.Error()))
			return
		}
		if err := msg.Validate(); err != nil {
			s.log.Warn("invalid campfire message", slog.String("error", err.Error()))
			return
		}
		s.log.Debug("dispatching campfire message",
			slog.String("lufrag", msg.LUfrag),
			slog.String("lpwd", msg.LPwd),
			slog.String("rufrag", msg.RUfrag),
			slog.String("rpwd", msg.RPwd),
			slog.String("type", msg.Type.String()),
		)
		s.handleCampFireMessage(msg, addr)
	}
	return
}

func (s *campFireManager) Close() error {
	close(s.closec)
	return s.PacketConn.Close()
}

func (s *campFireManager) handleCampFireMessage(msg *CampfireMessage, saddr net.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch msg.Type {
	case CampfireMessageAnnounce:
		s.handleAnnounce(msg, saddr)
	case CampfireMessageOffer:
		s.handleOffer(msg, saddr)
	case CampfireMessageAnswer:
		s.handleAnswer(msg, saddr)
	case CampfireMessageICE:
		s.handleICE(msg, saddr)
	}
}

func (s *campFireManager) handleAnnounce(msg *CampfireMessage, saddr net.Addr) {
	peer := peer{
		ufrag:       msg.LUfrag,
		pwd:         msg.LPwd,
		acceptUfrag: msg.RUfrag,
		acceptPwd:   msg.RPwd,
		expires:     msg.expires,
	}
	s.peers[peer] = saddr
}

func (s *campFireManager) handleOffer(msg *CampfireMessage, saddr net.Addr) {
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
	encoded, err := msg.Encode()
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

func (s *campFireManager) handleAnswer(msg *CampfireMessage, saddr net.Addr) {
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
	encoded, err := msg.Encode()
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

func (s *campFireManager) handleICE(msg *CampfireMessage, saddr net.Addr) {
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
	encoded, err := msg.Encode()
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
