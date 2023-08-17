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
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/net/websocket"
)

type campfireManager struct {
	net.PacketConn
	log    *slog.Logger
	peers  map[peer]io.WriteCloser
	closec chan struct{}
	mu     sync.Mutex
}

type peer struct {
	id          string
	ufrag       string
	pwd         string
	acceptUfrag string
	acceptPwd   string
	expires     int64
}

// NewCampfireManager creates a new campfire manager.
func NewCampfireManager(pc net.PacketConn, log *slog.Logger) *campfireManager {
	cm := &campfireManager{
		PacketConn: pc,
		log:        log,
		peers:      make(map[peer]io.WriteCloser),
		closec:     make(chan struct{}),
	}
	go cm.runPeerGC()
	return cm
}

func (s *campfireManager) ReadFrom(p []byte) (n int, addr net.Addr, rerr error) {
	if n, addr, rerr = s.PacketConn.ReadFrom(p); rerr == nil && IsCampfireMessage(p[:n]) {
		s.log.Debug("Handling CAMPFIRE packet", "saddr", addr.String(), "len", n)
		msg, err := DecodeCampfireMessage(p[:n])
		if err != nil {
			s.log.Warn("failed to decode campfire message", slog.String("error", err.Error()))
			return
		}
		if err := ValidateCampfireMessage(msg); err != nil {
			s.log.Warn("invalid campfire message", slog.String("error", err.Error()))
			return
		}
		s.log.Debug("Dispatching CAMPFIRE packet",
			slog.String("id", msg.Id),
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

func (s *campfireManager) Close() error {
	close(s.closec)
	return s.PacketConn.Close()
}

func (s *campfireManager) handleWebsocket(c *websocket.Conn) {}

func (s *campfireManager) handleCampFireMessage(pkt []byte, msg *v1.CampfireMessage, saddr net.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch msg.Type {
	case v1.CampfireMessage_ANNOUNCE:
		s.handleAnnouncePacket(msg, saddr)
	case v1.CampfireMessage_OFFER:
		s.handleOfferPacket(pkt, msg, saddr)
	case v1.CampfireMessage_ANSWER:
		s.handleAnswerPacket(pkt, msg, saddr)
	case v1.CampfireMessage_CANDIDATE:
		s.handleICEPacket(pkt, msg, saddr)
	}
}

func (s *campfireManager) handleAnnouncePacket(msg *v1.CampfireMessage, saddr net.Addr) {
	peer := peer{
		ufrag:       msg.Lufrag,
		pwd:         msg.Lpwd,
		acceptUfrag: msg.Rufrag,
		acceptPwd:   msg.Rpwd,
		expires:     nextExpiry(),
	}
	s.peers[peer] = &pktWriter{
		conn:  s.PacketConn,
		saddr: saddr,
	}
}

func (s *campfireManager) handleOfferPacket(pkt []byte, msg *v1.CampfireMessage, saddr net.Addr) {
	lpeer := peer{
		id:          msg.Id,
		ufrag:       msg.Lufrag,
		pwd:         msg.Lpwd,
		acceptUfrag: msg.Rufrag,
		acceptPwd:   msg.Rpwd,
		expires:     nextExpiry(),
	}
	s.peers[lpeer] = &pktWriter{
		conn:  s.PacketConn,
		saddr: saddr,
	}
	rpeer := peer{
		ufrag:       msg.Rufrag,
		pwd:         msg.Rpwd,
		acceptUfrag: msg.Lufrag,
		acceptPwd:   msg.Lpwd,
		expires:     nextExpiry(),
	}
	writer, ok := s.peers[rpeer]
	if !ok {
		s.log.Warn("No peer found for offer", slog.Any("peer", rpeer))
		return
	}
	s.log.Debug("Sending offer to peer", slog.Any("peer", rpeer))
	_, err := writer.Write(pkt)
	if err != nil {
		s.log.Warn("Error sending offer", slog.String("error", err.Error()))
		return
	}
	// Create a unique peer for the answer
	rpeer.id = msg.Id
	s.peers[rpeer] = &pktWriter{
		conn:  s.PacketConn,
		saddr: saddr,
	}
}

func (s *campfireManager) handleAnswerPacket(pkt []byte, msg *v1.CampfireMessage, saddr net.Addr) {
	lpeer := peer{
		id:          msg.Id,
		ufrag:       msg.Lufrag,
		pwd:         msg.Lpwd,
		acceptUfrag: msg.Rufrag,
		acceptPwd:   msg.Rpwd,
		expires:     nextExpiry(),
	}
	s.peers[lpeer] = &pktWriter{
		conn:  s.PacketConn,
		saddr: saddr,
	}
	rpeer := peer{
		id:          msg.Id,
		ufrag:       msg.Rufrag,
		pwd:         msg.Rpwd,
		acceptUfrag: msg.Lufrag,
		acceptPwd:   msg.Lpwd,
		expires:     nextExpiry(),
	}
	writer, ok := s.peers[rpeer]
	if !ok {
		s.log.Warn("No peer found for answer", slog.Any("peer", rpeer))
		return
	}
	s.log.Debug("Sending answer to peer", slog.Any("peer", rpeer))
	_, err := writer.Write(pkt)
	if err != nil {
		s.log.Warn("Error sending answer", slog.String("error", err.Error()))
		return
	}
}

func (s *campfireManager) handleICEPacket(pkt []byte, msg *v1.CampfireMessage, saddr net.Addr) {
	lpeer := peer{
		id:          msg.Id,
		ufrag:       msg.Lufrag,
		pwd:         msg.Lpwd,
		acceptUfrag: msg.Rufrag,
		acceptPwd:   msg.Rpwd,
		expires:     nextExpiry(),
	}
	s.peers[lpeer] = &pktWriter{
		conn:  s.PacketConn,
		saddr: saddr,
	}
	rpeer := peer{
		id:          msg.Id,
		ufrag:       msg.Rufrag,
		pwd:         msg.Rpwd,
		acceptUfrag: msg.Lufrag,
		acceptPwd:   msg.Lpwd,
		expires:     nextExpiry(),
	}
	writer, ok := s.peers[rpeer]
	if !ok {
		s.log.Warn("No peer found for ICE candidate", slog.Any("peer", rpeer))
		return
	}
	s.log.Debug("Sending ICE candidate to peer", slog.Any("peer", rpeer))
	_, err := writer.Write(pkt)
	if err != nil {
		s.log.Warn("Error sending ICE candidate", slog.String("error", err.Error()))
		return
	}
}

func (s *campfireManager) runPeerGC() {
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
					s.log.Debug("Removed expired peer", slog.Any("peer", peer), slog.Any("addr", addr))
				}
			}
			s.mu.Unlock()
		}
	}
}

// now is a variable for mocking time in tests.
var now = time.Now

func nextExpiry() int64 {
	return now().Truncate(time.Hour).Add(time.Hour).Unix()
}

type pktWriter struct {
	conn  net.PacketConn
	saddr net.Addr
}

func (p *pktWriter) Write(b []byte) (int, error) {
	return p.conn.WriteTo(b, p.saddr)
}

func (p *pktWriter) Close() error {
	return nil
}
