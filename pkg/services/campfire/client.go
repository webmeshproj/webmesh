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

	"github.com/google/uuid"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// Client is the campfire client.
type Client struct {
	*MessageStream
	id    string
	rooms []string
	oob   chan Message
	msgc  chan Message
	ackc  chan Message
	errc  chan Message
	log   *slog.Logger
	mu    sync.Mutex
}

// NewClient returns a new campfire client.
func NewClient(addr string) (*Client, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("generate uuid: %w", err)
	}
	return NewClientWithID(addr, id.String())
}

// NewClientWithID returns a new campfire client with the given id.
func NewClientWithID(addr, id string) (*Client, error) {
	c, err := net.Dial("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial udp: %w", err)
	}
	cl := &Client{
		MessageStream: NewMessageStream(c),
		id:            id,
		msgc:          make(chan Message, 3),
		oob:           make(chan Message, 3),
		ackc:          make(chan Message, 3),
		errc:          make(chan Message, 3),
		log:           slog.Default().With("client", "campfire"),
	}
	go cl.recvMessages()
	return cl, nil
}

// Join joins the room with the given name.
func (c *Client) Join(ctx context.Context, name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.SendMessage(Message{
		Type: MessageTypeJoin,
		From: c.id,
		Room: name,
	})
	if err != nil {
		return fmt.Errorf("send join message: %w", err)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case msg := <-c.errc:
		return fmt.Errorf("send join message: %s", msg.Body)
	case <-c.ackc:
	}
	c.rooms = append(c.rooms, name)
	return nil
}

// Leave leaves the room with the given name.
func (c *Client) Leave(ctx context.Context, name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.SendMessage(Message{
		Type: MessageTypeLeave,
		From: c.id,
		Room: name,
	})
	if err != nil {
		return fmt.Errorf("send leave message: %w", err)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case msg := <-c.errc:
		return fmt.Errorf("send leave message: %s", msg.Body)
	case <-c.ackc:
	}
	for i, room := range c.rooms {
		if room == name {
			c.rooms = append(c.rooms[:i], c.rooms[i+1:]...)
			break
		}
	}
	return nil
}

// List lists the members of the room with the given name.
func (c *Client) List(ctx context.Context, name string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.SendMessage(Message{
		Type: MessageTypeList,
		From: c.id,
		Room: name,
	})
	if err != nil {
		return nil, fmt.Errorf("send list message: %w", err)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg := <-c.errc:
		return nil, fmt.Errorf("send list message: %s", msg.Body)
	case <-c.ackc:
	}
	out := make([]string, 0)
	for {
		var msg Message
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case msg = <-c.msgc:
		}
		if err != nil {
			return nil, fmt.Errorf("recv list message: %w", err)
		}
		switch msg.Body {
		case EOF.Error():
			return out, nil
		case "":
			continue
		default:
			out = append(out, msg.Body)
		}
	}
}

// Send sends a message to the room with the given name. If
// to is not empty, the message is sent to the given recipient.
func (c *Client) Send(ctx context.Context, name, to, msg string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.SendMessage(Message{
		Type: MessageTypeMessage,
		From: c.id,
		Room: name,
		To:   to,
		Body: msg,
	})
	if err != nil {
		return fmt.Errorf("send message: %w", err)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case msg := <-c.errc:
		return fmt.Errorf("send message: %s", msg.Body)
	case <-c.ackc:
	}
	return nil
}

// Close closes the client and leaves all rooms.
func (c *Client) Close(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, room := range c.rooms {
		err := c.SendMessage(Message{
			Type: MessageTypeLeave,
			From: c.id,
			Room: room,
		})
		if err != nil {
			return fmt.Errorf("send leave message: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg := <-c.errc:
			return fmt.Errorf("leave room: %s", msg.Body)
		case <-c.ackc:
		}
	}
	return c.MessageStream.Close()
}

// Messages returns the message channel.
func (c *Client) Messages() <-chan Message {
	return c.oob
}

func (c *Client) recvMessages() {
	for {
		msg, err := c.RecvMessage()
		if err != nil {
			c.log.Error("recv message", "error", err)
			return
		}
		switch msg.Type {
		case MessageTypeACK:
			c.ackc <- msg
		case MessageTypeMessage:
			c.oob <- msg
		case MessageTypeError:
			c.errc <- msg
		default:
			c.msgc <- msg
		}
	}
}
