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
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/pion/webrtc/v3"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// Protocol is the campfire protocol.
const Protocol = protocol.ID("/webmesh/campfire/1.0.0")

// WaitingRoom is an interface for a waiting for others to join
// the campfire.
type WaitingRoom interface {
	// Connetions returns a channel that receives new incoming connections.
	Connections() <-chan Stream
	// Peers returns a channel that receives new peers that have joined the
	// campfire. A new stream to the peer is opened for each peer and sent
	// on the channel.
	Peers() <-chan Stream
	// Location returns the location of the campfire.
	Location() *Location
	// Errors returns a channel that receives errors.
	Errors() <-chan error
	// Close closes the waiting room.
	Close() error
}

// Stream is a campfire stream.
type Stream interface {
	// PeerID returns the peer ID of the remote peer.
	PeerID() peer.ID
	// SendCandidate sends an ICE candidate on the stream.
	// This is a convenience method for sending a Candidate message.
	SendCandidate(candidate string) error
	// SendOffer sends an SDP offer on the stream.
	// This is a convenience method for sending an SDP message.
	SendOffer(offer webrtc.SessionDescription) error
	// Send sends a message on the stream.
	Send(Message) error
	// Receive receives a message from the stream.
	Receive() (Message, error)
	// Close closes the stream.
	Close() error
}

type MessageType int

const (
	CandidateMessageType MessageType = iota
	SDPMessageType
)

// Message is a campfire message.
type Message struct {
	// Type is the type of message.
	Type MessageType
	// Candidate is an ICE candidate.
	Candidate string
	// SDP is an SDP offer or answer.
	SDP string
}

// UnmarshalSDP unmarshals the SDP into a SessionDescription.
func (m Message) UnmarshalSDP() (webrtc.SessionDescription, error) {
	var sdp webrtc.SessionDescription
	if err := json.Unmarshal([]byte(m.SDP), &sdp); err != nil {
		return webrtc.SessionDescription{}, fmt.Errorf("failed to unmarshal SDP: %w", err)
	}
	return sdp, nil
}

// waitingRoom is a simple implementation of WaitingRoom. It uses
// kad-dht to find peers.
type waitingRoom struct {
	loc    *Location
	host   host.Host
	dht    *dht.IpfsDHT
	connc  chan Stream
	peerc  chan Stream
	errc   chan error
	closec chan struct{}
}

// NewKadWaitingRoom creates a new waiting room using kad-dht to find peers.
func NewKadWaitingRoom(ctx context.Context, opts Options) (WaitingRoom, error) {
	log := context.LoggerFrom(ctx).With("protocol", "campfire", "component", "waiting-room")
	loc, err := Find(opts.PSK, opts.TURNServers)
	if err != nil {
		return nil, fmt.Errorf("failed to find campfire: %w", err)
	}
	log.Debug("found campfire", "location", loc)
	var room waitingRoom
	room.loc = loc
	room.connc = make(chan Stream, 3)
	room.peerc = make(chan Stream, 3)
	room.errc = make(chan error, 3)
	room.closec = make(chan struct{})
	room.host, err = libp2p.New(libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"))
	if err != nil {
		return nil, fmt.Errorf("failed to create host: %w", err)
	}
	room.host.SetStreamHandler(Protocol, func(stream network.Stream) {
		log.Info("Incoming stream from the campfire", "peer", stream.Conn().RemotePeer())
		room.connc <- newNetworkStream(stream)
	})
	log.Debug("started libp2p host", "id", room.host.ID())
	room.dht, err = dht.New(ctx, room.host)
	if err != nil {
		return nil, fmt.Errorf("failed to create dht: %w", err)
	}
	log.Debug("bootstrapping the DHT")
	if err := room.dht.Bootstrap(ctx); err != nil {
		return nil, fmt.Errorf("failed to bootstrap dht: %w", err)
	}
	var wg sync.WaitGroup
	for _, peerAddr := range dht.DefaultBootstrapPeers {
		peerinfo, _ := peer.AddrInfoFromP2pAddr(peerAddr)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := room.host.Connect(ctx, *peerinfo); err != nil {
				log.Warn("Error connectiong to host", "error", err.Error())
			} else {
				log.Debug("Connection established with bootstrap node", "peer", *peerinfo)
			}
		}()
	}
	wg.Wait()
	routingDiscovery := routing.NewRoutingDiscovery(room.dht)
	dutil.Advertise(ctx, routingDiscovery, room.loc.Secret, discovery.TTL(time.Hour))
	log.Info("DHT bootstrapped, waiting by the camp fire...")
	go func() {
		peerinfo, err := routingDiscovery.FindPeers(ctx, room.loc.Secret)
		if err != nil {
			log.Error("failed to find peers", "error", err.Error())
			room.errc <- err
			return
		}
		for {
			select {
			case <-room.closec:
				return
			case peer := <-peerinfo:
				if peer.ID == room.host.ID() || peer.ID == "" {
					continue
				}
				log.Info("Found a peer at the camp fire", "peer", peer.ID)
				stream, err := room.host.NewStream(ctx, peer.ID, Protocol)
				if err != nil {
					if errors.Is(err, context.Canceled) {
						return
					}
					if strings.Contains(err.Error(), "connection refused") {
						log.Debug("peer connection refused, they probably left the campfire", "peer", peer.ID)
						continue
					}
					log.Error("failed to open stream to peer", "error", err.Error())
					room.errc <- err
					continue
				}
				room.peerc <- newNetworkStream(stream)
			}
		}
	}()
	return &room, nil
}

// Connections returns a channel that receives new incoming connections.
func (w *waitingRoom) Connections() <-chan Stream {
	return w.connc
}

// Peers returns a channel that receives new peers that have joined the
// campfire.
func (w *waitingRoom) Peers() <-chan Stream {
	return w.peerc
}

// Location returns the location of the campfire.
func (w *waitingRoom) Location() *Location {
	return w.loc
}

// Errors returns a channel that receives errors.
func (w *waitingRoom) Errors() <-chan error {
	return w.errc
}

// Close closes the waiting room.
func (w *waitingRoom) Close() error {
	close(w.closec)
	defer w.dht.Close()
	return w.host.Close()
}

type networkStream struct {
	network.Stream
	rw *bufio.ReadWriter
}

func newNetworkStream(stream network.Stream) *networkStream {
	return &networkStream{
		Stream: stream,
		rw:     bufio.NewReadWriter(bufio.NewReader(stream), bufio.NewWriter(stream)),
	}
}

// PeerID returns the peer ID of the remote peer.
func (nw *networkStream) PeerID() peer.ID {
	return nw.Conn().RemotePeer()
}

// SendCandidate sends an ICE candidate on the stream.
// This is a convenience method for sending a Candidate message.
func (nw *networkStream) SendCandidate(candidate string) error {
	return nw.Send(Message{
		Type:      CandidateMessageType,
		Candidate: candidate,
	})
}

// SendOffer sends an SDP offer on the stream.
// This is a convenience method for sending an SDP message.
func (nw *networkStream) SendOffer(offer webrtc.SessionDescription) error {
	data, err := json.Marshal(offer)
	if err != nil {
		return fmt.Errorf("failed to marshal SDP: %w", err)
	}
	return nw.Send(Message{
		Type: SDPMessageType,
		SDP:  string(data),
	})
}

// Send sends a message on the stream.
func (nw *networkStream) Send(msg Message) error {
	out, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}
	out = append(out, []byte("\n")...)
	if _, err := nw.rw.Write(out); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}
	if err := nw.rw.Flush(); err != nil {
		return fmt.Errorf("failed to flush message: %w", err)
	}
	return nil
}

// Receive receives a message from the stream.
func (nw *networkStream) Receive() (Message, error) {
	data, err := nw.rw.ReadBytes('\n')
	if err != nil {
		return Message{}, fmt.Errorf("failed to read message: %w", err)
	}
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return Message{}, fmt.Errorf("failed to unmarshal message: %w", err)
	}
	return msg, nil
}

// Close closes the stream.
func (nw *networkStream) Close() error {
	return nw.Stream.Close()
}
