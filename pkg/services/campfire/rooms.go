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
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/meshdb"
)

// RoomManager is the room manager.
type RoomManager struct {
	pkt   net.PacketConn
	mesh  meshdb.Store
	rooms map[string]*room
	mu    sync.Mutex
	log   *slog.Logger
}

// NewRoomManager returns a new room manager.
func NewRoomManager(mesh meshdb.Store, c net.PacketConn) *RoomManager {
	return &RoomManager{
		pkt:   c,
		mesh:  mesh,
		rooms: make(map[string]*room),
		log:   slog.Default().With("service", "campfire"),
	}
}

type room struct {
	// key is the pre-shared key for the room.
	key string
	// members is a map of member ids to members.
	members map[string]*member
}

type member struct {
	// id is the member id.
	id string
	// addr is the member's address.
	addr net.Addr
	// lastSeen is the last time the member was seen.
	lastSeen time.Time
}

// HandleMessage handles a campfire message.
func (r *RoomManager) HandleMessage(srcaddr net.Addr, msg *Message) {
	r.mu.Lock()
	defer r.mu.Unlock()
	group, ok := r.rooms[msg.Room]
	if !ok {
		r.rooms[msg.Room] = &room{
			key:     msg.Room,
			members: make(map[string]*member),
		}
		group = r.rooms[msg.Room]
	}
	switch msg.Type {
	case MessageTypeJoin:
		r.log.Debug("got join message", "from", msg.From, "room", msg.Room)
		group.members[msg.From] = &member{
			id:       msg.From,
			addr:     srcaddr,
			lastSeen: time.Now().UTC(),
		}
		err := r.sendAck(srcaddr)
		if err != nil {
			r.log.Error("failed to send ack", "error", err)
		}
	case MessageTypeLeave:
		r.log.Debug("got leave message", "from", msg.From, "room", msg.Room)
		delete(group.members, msg.From)
		err := r.sendAck(srcaddr)
		if err != nil {
			r.log.Error("failed to send ack", "error", err)
			// We still want to cleanup the room if the ack fails
		}
		if len(group.members) == 0 {
			delete(r.rooms, msg.Room)
		}
	case MessageTypeList:
		r.log.Debug("got list message", "from", msg.From, "room", msg.Room)
		// Ack the request first before we begin
		err := r.sendAck(srcaddr)
		if err != nil {
			r.log.Error("failed to send ack", "error", err)
			return
		}
		var m Message
		m.Type = MessageTypeList
		m.Room = msg.Room
		for _, member := range group.members {
			if member.id == msg.From {
				member.lastSeen = time.Now().UTC()
				continue
			}
			m.Body = member.id
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
		r.log.Debug("got message", "from", msg.From, "room", msg.Room, "to", msg.To)
		for _, member := range group.members {
			if member.id == msg.From {
				member.lastSeen = time.Now().UTC()
				continue
			}
			if member.id == to || to == msg.Room {
				err := r.sendToMember(member.addr, msg)
				if err != nil {
					r.log.Error("failed to send message", "error", err)
				}
				if member.id == to {
					break
				}
			}
		}
		err := r.sendAck(srcaddr)
		if err != nil {
			r.log.Error("failed to send ack", "error", err)
		}
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

func (r *RoomManager) sendAck(addr net.Addr) error {
	r.log.Debug("sending ack", "to", addr)
	b, err := (&Message{
		Type: MessageTypeACK,
	}).Encode()
	if err != nil {
		return fmt.Errorf("failed to encode ack: %w", err)
	}
	_, err = r.pkt.WriteTo(b, addr)
	return err
}
