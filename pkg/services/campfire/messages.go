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
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
)

// MessageType is a message type.
type MessageType int

const (
	// MessageTypeUnknown is an unknown message type.
	MessageTypeUnknown MessageType = iota
	// MessageTypeJoin is a join message type.
	MessageTypeJoin
	// MessageTypeLeave is a leave message type.
	MessageTypeLeave
	// MessageTypeList is a list message type.
	MessageTypeList
	// MessageTypeMessage is a message message type.
	MessageTypeMessage
	// MessageTypeMember is a member message type.
	// This is a server-only message type.
	MessageTypeMember
	// MessageTypeACK is an ACK message type.
	// This is a server-only message type.
	MessageTypeACK
)

// Message is a campfire message.
type Message struct {
	// Type is the message type.
	Type MessageType
	// Room is the room.
	Room string
	// From is the sender.
	From string
	// To is the recipient.
	To string
	// Body is the message body.
	Body string
}

// ParseMessage parses a message from the wire form.
func ParseMessage(b []byte) (Message, error) {
	var m Message
	err := gob.NewDecoder(bytes.NewReader(b)).Decode(&m)
	return m, err
}

// Encode encodes a message to wire form.
func (m Message) Encode() ([]byte, error) {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(m)
	return buf.Bytes(), err
}

type MessageStream struct {
	net.Conn
}

func NewMessageStream(c net.Conn) *MessageStream {
	return &MessageStream{Conn: c}
}

func (m *MessageStream) SendMessage(msg Message) error {
	b, err := msg.Encode()
	if err != nil {
		return err
	}
	_, err = m.Write(b)
	if err != nil {
		return err
	}
	ack, err := m.RecvMessage()
	if err != nil {
		return err
	}
	if ack.Type != MessageTypeACK {
		return fmt.Errorf("expected ACK, got %d", ack.Type)
	}
	return err
}

func (m *MessageStream) RecvMessage() (Message, error) {
	var msg Message
	err := gob.NewDecoder(m).Decode(&msg)
	return msg, err
}
