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

// Package datachannels provides a WebRTC data channel API for port forwarding.
package datachannels

// ServerChannel is a server-side data channel.
type ServerChannel interface {
	// Offer returns the offer for the data channel.
	Offer() string
	// AnswerOffer answers the offer from the peer.
	AnswerOffer(offer string) error
	// Candidates returns a channel for receiving ICE candidates.
	Candidates() <-chan string
	// AddCandidate adds an ICE candidate.
	AddCandidate(candidate string) error
	// Closed returns a channel for receiving a notification when the data channel is closed.
	Closed() <-chan struct{}
	// Close closes the data channel.
	Close() error
}
