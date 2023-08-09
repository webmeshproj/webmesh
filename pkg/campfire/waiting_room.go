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

	"github.com/pion/webrtc/v3"
)

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
	PeerID() string
	// SendCandidate sends an ICE candidate on the stream.
	// This is a convenience method for sending a Candidate message.
	SendCandidate(candidate string) error
	// SendOffer sends an SDP offer on the stream.
	// This is a convenience method for sending an SDP message.
	SendOffer(offer webrtc.SessionDescription) error
	// Receive receives a message from the stream.
	Receive() (Message, error)
	// Close closes the stream.
	Close() error
}

// MessageType indicates the type of message sent
// to a peer in a waiting room.
type MessageType int

const (
	// CandidateMessageType is a message containing an ICE candidate.
	CandidateMessageType MessageType = iota
	// SDPMessageType is a message containing an SDP offer or answer.
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

// NewSDPMessage creates a new SDP message.
func NewSDPMessage(sdp webrtc.SessionDescription) (Message, error) {
	b, err := json.Marshal(sdp)
	if err != nil {
		return Message{}, fmt.Errorf("failed to marshal SDP: %w", err)
	}
	return Message{
		Type: SDPMessageType,
		SDP:  string(b),
	}, nil
}

// NewCandidateMessage creates a new candidate message.
func NewCandidateMessage(candidate string) Message {
	return Message{
		Type:      CandidateMessageType,
		Candidate: candidate,
	}
}
