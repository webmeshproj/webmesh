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
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/pion/webrtc/v3"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/services/campfire"
)

type webmeshWaitingRoom struct {
	loc     *Location
	cli     *campfire.Client
	connc   chan Stream
	peerc   chan Stream
	errc    chan error
	closec  chan struct{}
	streams map[string]*webmeshCampfireStream
	log     *slog.Logger
	mu      sync.Mutex
}

func NewWebmeshWaitingRoom(ctx context.Context, campfireServer string, opts Options) (WaitingRoom, error) {
	log := context.LoggerFrom(ctx).With("protocol", "campfire", "component", "waiting-room", "type", "webmesh")
	loc, err := Find(opts.PSK, opts.TURNServers)
	if err != nil {
		return nil, fmt.Errorf("failed to find campfire: %w", err)
	}
	log.Debug("found campfire location", "location", loc)
	conn, err := campfire.NewClient(campfireServer)
	if err != nil {
		return nil, fmt.Errorf("failed to dial turn server: %w", err)
	}
	err = conn.Join(ctx, loc.Secret)
	if err != nil {
		return nil, fmt.Errorf("failed to join campfire: %w", err)
	}
	room := &webmeshWaitingRoom{
		cli:     conn,
		loc:     loc,
		connc:   make(chan Stream, 3),
		peerc:   make(chan Stream, 3),
		errc:    make(chan error, 3),
		closec:  make(chan struct{}),
		streams: make(map[string]*webmeshCampfireStream),
		log:     log,
	}
	log.Debug("waiting by the camp fire", "id", room.cli.ID())
	go room.handleClient()
	return room, nil
}

func (wm *webmeshWaitingRoom) handleClient() {
	recvc := make(chan campfire.Message, 3)
	go func() {
		for msg := range wm.cli.Messages() {
			recvc <- msg
		}
	}()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-wm.closec:
			return
		case msg := <-recvc:
			if msg.Body == "START STREAM" {
				// Incoming new stream
				stream := &webmeshCampfireStream{
					peerID: msg.From,
					room:   wm,
					msgc:   make(chan Message, 3),
					closec: make(chan struct{}),
				}
				wm.mu.Lock()
				if _, ok := wm.streams[msg.From]; ok {
					continue
				}
				wm.streams[msg.From] = stream
				wm.connc <- stream
				wm.mu.Unlock()
				continue
			}
			if msg.Body == "END STREAM" {
				// Incoming stream close
				wm.mu.Lock()
				if stream, ok := wm.streams[msg.From]; ok {
					close(stream.msgc)
					delete(wm.streams, msg.From)
				}
				wm.mu.Unlock()
				continue
			}
			wm.mu.Lock()
			stream, ok := wm.streams[msg.From]
			if !ok {
				continue
			}
			var m Message
			err := json.Unmarshal([]byte(msg.Body), &m)
			if err != nil {
				wm.errc <- fmt.Errorf("failed to unmarshal message: %w", err)
				continue
			}
			stream.msgc <- m
			wm.mu.Unlock()
		case <-t.C:
			peers, err := wm.cli.List(context.Background(), wm.loc.Secret)
			if err != nil {
				wm.errc <- fmt.Errorf("failed to list peers: %w", err)
				continue
			}
			wm.mu.Lock()
			for _, peer := range peers {
				if _, ok := wm.streams[peer]; ok {
					continue
				}
				err := wm.cli.Send(context.Background(), wm.loc.Secret, peer, "START STREAM")
				if err != nil {
					wm.errc <- fmt.Errorf("failed to send start stream message: %w", err)
					continue
				}
				stream := &webmeshCampfireStream{
					peerID: peer,
					room:   wm,
					msgc:   make(chan Message, 3),
					closec: make(chan struct{}),
				}
				wm.streams[peer] = stream
				wm.peerc <- stream
			}
			wm.mu.Unlock()
		}
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
	return wm.cli.Close(context.Background())
}

type webmeshCampfireStream struct {
	peerID string
	room   *webmeshWaitingRoom
	msgc   chan Message
	closec chan struct{}
}

// PeerID returns the peer ID of the remote peer.
func (w *webmeshCampfireStream) PeerID() string {
	return w.peerID
}

// SendCandidate sends an ICE candidate on the stream.
// This is a convenience method for sending a Candidate message.
func (w *webmeshCampfireStream) SendCandidate(candidate string) error {
	select {
	case <-w.closec:
		return fmt.Errorf("stream closed")
	default:
	}
	msg := NewCandidateMessage(candidate)
	b, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal candidate message: %w", err)
	}
	err = w.room.cli.Send(context.Background(), w.room.loc.Secret, w.peerID, string(b))
	if err != nil {
		return fmt.Errorf("failed to send candidate message: %w", err)
	}
	return nil
}

// SendOffer sends an SDP offer on the stream.
// This is a convenience method for sending an SDP message.
func (w *webmeshCampfireStream) SendOffer(offer webrtc.SessionDescription) error {
	select {
	case <-w.closec:
		return fmt.Errorf("stream closed")
	default:
	}
	msg, err := NewSDPMessage(offer)
	if err != nil {
		return fmt.Errorf("failed to create SDP message: %w", err)
	}
	b, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal SDP message: %w", err)
	}
	err = w.room.cli.Send(context.Background(), w.room.loc.Secret, w.peerID, string(b))
	if err != nil {
		return fmt.Errorf("failed to send SDP message: %w", err)
	}
	return nil
}

// Receive receives a message from the stream.
func (w *webmeshCampfireStream) Receive() (Message, error) {
	select {
	case <-w.closec:
		return Message{}, io.EOF
	case msg := <-w.msgc:
		return msg, nil
	}
}

// Close closes the stream.
func (w *webmeshCampfireStream) Close() error {
	err := w.room.cli.Send(context.Background(), w.room.loc.Secret, w.peerID, "END STREAM")
	if err != nil {
		return fmt.Errorf("failed to send end stream message: %w", err)
	}
	close(w.closec)
	return nil
}
