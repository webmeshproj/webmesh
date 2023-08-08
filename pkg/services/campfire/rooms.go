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

package campfire

import (
	"context"
	"fmt"
	"net"
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/meshdb"
)

const (
	// CampFirePrefix is the prefix for campfire service paths.
	CampFirePrefix = "/campfire"
	// RoomsPrefix is the prefix for campfire rooms.
	RoomsPrefix = CampFirePrefix + "/rooms"
)

// RoomManager is the room manager.
type RoomManager struct {
	pkt        net.PacketConn
	mesh       meshdb.Store
	log        *slog.Logger
	cancelSubs func()
	mu         sync.Mutex
}

// NewRoomManager returns a new room manager.
func NewRoomManager(mesh meshdb.Store, c net.PacketConn) (*RoomManager, error) {
	rm := &RoomManager{
		pkt:  c,
		mesh: mesh,
		log:  slog.Default().With("service", "campfire"),
	}
	cancel, err := mesh.Storage().Subscribe(context.Background(), RoomsPrefix, rm.handleSubscription)
	if err != nil {
		return nil, fmt.Errorf("subscribe to rooms: %w", err)
	}
	rm.cancelSubs = cancel
	return rm, nil
}

func (r *RoomManager) handleSubscription(key, value string) {
	key = strings.TrimPrefix(key, RoomsPrefix+"/")
	parts := strings.Split(key, "/")
	if len(parts) < 2 {
		return
	}
	room := parts[0]
	if parts[1] == "messages" {
		if len(parts) < 5 {
			return
		}
		from, to, recvAt := parts[2], parts[3], parts[4]
		r.log.Debug("dispatching message", "room", room, "from", from, "to", to, "recvAt", recvAt)
		var members []string
		if to == room {
			var err error
			members, err = r.mesh.Storage().List(context.Background(), path.Join(RoomsPrefix, room, "members"))
			if err != nil {
				r.log.Error("failed to list members", "error", err)
				return
			}
		} else {
			members = []string{to}
		}
		for _, member := range members {
			memberID := path.Base(member)
			if memberID == from {
				continue
			}
			addr, err := r.mesh.Storage().Get(context.Background(), path.Join(RoomsPrefix, room, "members", memberID))
			if err != nil {
				r.log.Error("failed to get member", "error", err)
				continue
			}
			uaddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				r.log.Error("failed to resolve udp addr", "error", err)
				continue
			}
			msg := Message{
				Type: MessageTypeMessage,
				Room: room,
				From: from,
				To:   to,
				Body: value,
			}
			err = r.sendToMember(uaddr, &msg)
			if err != nil {
				r.log.Error("failed to send message", "error", err)
			}
		}
	}
}

// Close closes the room manager.
func (r *RoomManager) Close() {
	r.cancelSubs()
}

// HandleMessage handles a campfire message.
func (r *RoomManager) HandleMessage(srcaddr net.Addr, msg *Message) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ctx := context.Background()
	switch msg.Type {
	case MessageTypeJoin:
		r.log.Debug("got join message", "from", msg.From, "room", msg.Room)
		key := path.Join(RoomsPrefix, msg.Room, "members", msg.From)
		err := r.mesh.Storage().Put(ctx, key, srcaddr.String(), 0)
		if err != nil {
			r.log.Error("failed to add member", "error", err)
			r.sendError(srcaddr, err)
			return
		}
		r.sendAck(srcaddr)
	case MessageTypeLeave:
		r.log.Debug("got leave message", "from", msg.From, "room", msg.Room)
		key := path.Join(RoomsPrefix, msg.Room, "members", msg.From)
		err := r.mesh.Storage().Delete(ctx, key)
		if err != nil {
			r.log.Error("failed to delete member", "error", err)
			r.sendError(srcaddr, err)
			return
		}
		r.sendAck(srcaddr)
	case MessageTypeList:
		r.log.Debug("got list message", "from", msg.From, "room", msg.Room)
		// Ack the request first before we begin
		r.sendAck(srcaddr)
		members, err := r.mesh.Storage().List(ctx, path.Join(RoomsPrefix, msg.Room, "members"))
		if err != nil {
			r.log.Error("failed to list members", "error", err)
			r.sendError(srcaddr, err)
			return
		}
		var m Message
		m.Type = MessageTypeList
		m.Room = msg.Room
		for _, member := range members {
			memberID := path.Base(member)
			if memberID == msg.From {
				continue
			}
			m.Body = memberID
			err := r.sendToMember(srcaddr, &m)
			if err != nil {
				r.log.Error("failed to send list", "error", err)
			}
		}
		m.Body = EOF.Error()
		err = r.sendToMember(srcaddr, &m)
		if err != nil {
			r.log.Error("failed to send EOF", "error", err)
		}
	case MessageTypeMessage:
		to := msg.To
		if to == "" {
			to = msg.Room
		}
		r.log.Debug("got message", "from", msg.From, "room", msg.Room, "to", to)
		key := path.Join(RoomsPrefix, msg.Room, "messages", msg.From, to, time.Now().UTC().Format(time.RFC3339Nano))
		err := r.mesh.Storage().Put(ctx, key, msg.Body, time.Minute)
		if err != nil {
			r.log.Error("failed to store message", "error", err)
			r.sendError(srcaddr, err)
			return
		}
		r.sendAck(srcaddr)
	}
}

func (r *RoomManager) sendToMember(addr net.Addr, msg *Message) error {
	r.log.Debug("sending message", "to", addr, "message", msg)
	b, err := msg.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode message: %w", err)
	}
	_, err = r.pkt.WriteTo(b, addr)
	return err
}

func (r *RoomManager) sendAck(addr net.Addr) {
	r.log.Debug("sending ack", "to", addr)
	b, err := (&Message{
		Type: MessageTypeACK,
	}).Encode()
	if err != nil {
		r.log.Error("failed to encode ack", "error", err)
	}
	_, err = r.pkt.WriteTo(b, addr)
	if err != nil {
		r.log.Error("failed to send ack", "error", err)
	}
}

func (r *RoomManager) sendError(addr net.Addr, err error) {
	r.log.Debug("sending error", "to", addr)
	b, err := (&Message{
		Type: MessageTypeError,
		Body: err.Error(),
	}).Encode()
	if err != nil {
		r.log.Error("failed to encode error", "error", err)
		return
	}
	_, err = r.pkt.WriteTo(b, addr)
	if err != nil {
		r.log.Error("failed to send error", "error", err)
	}
}
