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
	"strings"

	"github.com/google/uuid"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/context"
	capi "github.com/webmeshproj/webmesh/pkg/services/campfire"
)

type webmeshWaitingRoom struct {
	id     string
	conn   net.Conn
	loc    *Location
	connc  chan Stream
	peerc  chan Stream
	errc   chan error
	closec chan struct{}
	log    *slog.Logger
}

func NewWebmeshWaitingRoom(ctx context.Context, opts Options) (WaitingRoom, error) {
	log := context.LoggerFrom(ctx).With("protocol", "campfire", "component", "waiting-room", "type", "webmesh")
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate id: %w", err)
	}
	loc, err := Find(opts.PSK, opts.TURNServers)
	if err != nil {
		return nil, fmt.Errorf("failed to find campfire: %w", err)
	}
	log.Debug("found campfire", "location", loc)
	loc.TURNServer = strings.TrimPrefix(loc.TURNServer, "turn:")
	conn, err := net.Dial("udp", loc.TURNServer)
	if err != nil {
		return nil, fmt.Errorf("failed to dial turn server: %w", err)
	}
	room := &webmeshWaitingRoom{
		id:     id.String(),
		conn:   conn,
		loc:    loc,
		connc:  make(chan Stream, 3),
		peerc:  make(chan Stream, 3),
		errc:   make(chan error, 3),
		closec: make(chan struct{}),
		log:    log,
	}
	go room.handleConn()
	return room, nil
}

func (wm *webmeshWaitingRoom) handleConn() {
	wm.log.Debug("connected to campfire")
	stream := capi.NewMessageStream(wm.conn)
	err := stream.SendMessage(capi.Message{
		Type: capi.MessageTypeJoin,
		Room: wm.loc.Secret,
		From: wm.id,
	})
	if err != nil {
		wm.errc <- fmt.Errorf("failed to send join message: %w", err)
		return
	}
}

// Connetions returns a channel that receives new incoming connections.
func (wm *webmeshWaitingRoom) Connections() <-chan Stream {
	return wm.connc
}

// Peers returns a channel that receives new peers that have joined the
// campfire. A new stream to the peer is opened for each peer and sent
// on the channel.
func (wm *webmeshWaitingRoom) Peers() <-chan Stream {
	return wm.peerc
}

// Location returns the location of the campfire.
func (wm *webmeshWaitingRoom) Location() *Location {
	return wm.loc
}

// Errors returns a channel that receives errors.
func (wm *webmeshWaitingRoom) Errors() <-chan error {
	return wm.errc
}

// Close closes the waiting room.
func (wm *webmeshWaitingRoom) Close() error {
	wm.log.Debug("leaving the campfire")
	defer close(wm.closec)
	msg := capi.Message{
		Type: capi.MessageTypeLeave,
		Room: wm.loc.Secret,
		From: wm.id,
	}
	b, err := msg.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode leave message: %w", err)
	}
	_, err = wm.conn.Write(b)
	if err != nil {
		return fmt.Errorf("failed to write leave message: %w", err)
	}
	return wm.conn.Close()
}
