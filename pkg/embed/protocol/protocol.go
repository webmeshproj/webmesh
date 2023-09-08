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

// Package protocol defines the libp2p webmesh protocol.
package protocol

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

func init() {
	if err := multiaddr.AddProtocol(Protocol); err != nil {
		panic(err)
	}
}

// Code is the code for the webmesh libp2p protocol.
const Code = 613

// ErrNoPeerID is returned when a webmesh multiaddr does not contain a peer ID.
var ErrNoPeerID = fmt.Errorf("no peer ID in webmesh multiaddr")

// ErrNoRedezvous is returned when a webmesh multiaddr does not contain a rendezvous.
var ErrNoRedezvous = fmt.Errorf("no rendezvous in webmesh multiaddr")

// Protocol is the webmesh libp2p protocol.
var Protocol = multiaddr.Protocol{
	Name:       "webmesh",
	Code:       Code,
	VCode:      multiaddr.CodeToVarint(Code),
	Size:       -1,
	Path:       true,
	Transcoder: multiaddr.NewTranscoderFromFunctions(protocolStrToBytes, protocolBytesToStr, validateBytes),
}

// PeerIDFromWebmeshAddr returns the peer ID argument from a webmesh multiaddr.
func PeerIDFromWebmeshAddr(addr multiaddr.Multiaddr) (peer.ID, error) {
	pid, err := addr.ValueForProtocol(Code)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNoPeerID, err)
	}
	if pid == "" {
		return "", fmt.Errorf("%w: %s", ErrNoPeerID, addr)
	}
	parts := strings.SplitN(strings.TrimPrefix(pid, "/"), "/", 2)
	return peer.ID(parts[0]), nil
}

// RendezvousFromWebmeshAddr returns the rendezvous argument from a webmesh multiaddr.
func RendezvousFromWebmeshAddr(addr multiaddr.Multiaddr) (string, error) {
	rendezvous, err := addr.ValueForProtocol(Code)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNoRedezvous, err)
	}
	if rendezvous == "" {
		return "", fmt.Errorf("%w: %s", ErrNoRedezvous, addr)
	}
	parts := strings.SplitN(strings.TrimPrefix(rendezvous, "/"), "/", 2)
	if len(parts) < 2 {
		return "", fmt.Errorf("%w: %s", ErrNoRedezvous, addr)
	}
	return parts[1], nil
}

func protocolStrToBytes(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func protocolBytesToStr(b []byte) (string, error) {
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func validateBytes(b []byte) error {
	_, err := base64.RawURLEncoding.DecodeString(string(b))
	return err
}
