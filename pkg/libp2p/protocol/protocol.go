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

const (
	// SecurityID is the protocol ID of the security protocol.
	SecurityID = "/webmesh/1.0.0"
	// ID is the ID for the webmesh libp2p transport protocol.
	ProtocolID = "webmesh-v1"
	// MuxerID is the ID for the webmesh libp2p multiplexer.
	MuxerID = "/webmesh/wireguard/1.0.0"
	// ProtocolPath is the path for the webmesh libp2p transport protocol.
	ProtocolPath = "/" + ProtocolID
	// ProtocolCode is the code for the webmesh libp2p transport protocol.
	ProtocolCode = 613
	// P_WEBMESH is the code for the webmesh libp2p protocol.
	P_WEBMESH = ProtocolCode
	// SignalingPort is the port assumed for signaling.
	SignalingPort = 61820
	// PrefixSize is the size of the remote local address prefix.
	PrefixSize = 112
)

// ErrNoPeerID is returned when a webmesh multiaddr does not contain a peer ID.
var ErrNoPeerID = fmt.Errorf("no peer ID in webmesh multiaddr")

// ErrNoRedezvous is returned when a webmesh multiaddr does not contain a rendezvous.
var ErrNoRedezvous = fmt.Errorf("no rendezvous in webmesh multiaddr")

// Protocol is the webmesh libp2p protocol.
var Protocol = multiaddr.Protocol{
	Name:       ProtocolID,
	Code:       P_WEBMESH,
	VCode:      multiaddr.CodeToVarint(P_WEBMESH),
	Size:       -1,
	Path:       false,
	Transcoder: multiaddr.NewTranscoderFromFunctions(protocolStrToBytes, protocolBytesToStr, validateBytes),
}

// Decapsulate strips the webmesh component from the given multiaddr.
func Decapsulate(addr multiaddr.Multiaddr) multiaddr.Multiaddr {
	spl := strings.Split(addr.String(), ProtocolID)
	spl[0] = strings.TrimSuffix(spl[0], "/")
	return multiaddr.StringCast(spl[0])
}

// Encapsulate appends the webmesh protocol to the given address.
func Encapsulate(addr multiaddr.Multiaddr, pid peer.ID) multiaddr.Multiaddr {
	return multiaddr.Join(addr, multiaddr.StringCast(ProtocolPath+"/"+pid.String()))
}

// IsWebmeshCapableAddr returns true if the given multiaddr is a webmesh-capable multiaddr.
func IsWebmeshCapableAddr(addr multiaddr.Multiaddr) bool {
	return (IsWebmeshAddr(addr) || IsUnencryptedAddr(addr)) &&
		(!IsWebtransportAddr(addr) && !IsQUICAddr(addr))
}

// IsWebmeshAddr returns true if the given multiaddr is a webmesh multiaddr.
func IsWebmeshAddr(addr multiaddr.Multiaddr) bool {
	var hasWebmesh bool
	multiaddr.ForEach(addr, func(c multiaddr.Component) bool {
		switch c.Protocol().Code {
		case P_WEBMESH:
			hasWebmesh = true
			return false
		}
		return true
	})
	return hasWebmesh
}

// IsWebtransportAddr returns true if the given multiaddr is a webtransport multiaddr.
func IsWebtransportAddr(addr multiaddr.Multiaddr) bool {
	var hasWebTransport bool
	multiaddr.ForEach(addr, func(c multiaddr.Component) bool {
		switch c.Protocol().Code {
		case multiaddr.P_WEBTRANSPORT:
			hasWebTransport = true
			return false
		}
		return true
	})
	return hasWebTransport
}

// IsQUICAddr returns true if the given multiaddr is a QUIC multiaddr.
func IsQUICAddr(addr multiaddr.Multiaddr) bool {
	var hasQuicTransport bool
	multiaddr.ForEach(addr, func(c multiaddr.Component) bool {
		switch c.Protocol().Code {
		case multiaddr.P_QUIC:
			hasQuicTransport = true
			return false
		case multiaddr.P_QUIC_V1:
			hasQuicTransport = true
			return false
		}
		return true
	})
	return hasQuicTransport
}

// IsUnencryptedAddr returns true if the given multiaddr is an unencrypted multiaddr.
func IsUnencryptedAddr(addr multiaddr.Multiaddr) bool {
	var hasEncryption bool
	multiaddr.ForEach(addr, func(c multiaddr.Component) bool {
		switch c.Protocol().Code {
		case multiaddr.P_CERTHASH:
			hasEncryption = true
		case multiaddr.P_NOISE:
			hasEncryption = true
		}
		return true
	})
	return !hasEncryption
}

// DecapsulateAddr returns the protocol and port from the multiaddr
func DecapsulateAddr(addr multiaddr.Multiaddr) (protocol string, port string, err error) {
	multiaddr.ForEach(addr, func(c multiaddr.Component) bool {
		switch c.Protocol().Code {
		case multiaddr.P_TCP:
			protocol = "tcp"
			port = c.Value()
			return false
		case multiaddr.P_UDP:
			protocol = "udp"
			port = c.Value()
			return false
		}
		return true
	})
	if protocol == "" && port == "" {
		return "", "", fmt.Errorf("no protocol or port in multiaddr")
	}
	return protocol, port, nil
}

// WithPeerID returns a webmesh multiaddr with the given peer ID.
func WithPeerID(pid peer.ID) multiaddr.Multiaddr {
	return multiaddr.StringCast(fmt.Sprintf("/%s/%s", ProtocolID, pid.String()))
}

// WithPeerIDAndRendezvous returns a webmesh multiaddr with the given peer ID and rendezvous.
func WithPeerIDAndRendezvous(pid peer.ID, rendezvous string) multiaddr.Multiaddr {
	return multiaddr.StringCast(fmt.Sprintf("/%s/%s/%s", ProtocolID, pid.String(), rendezvous))
}

// PeerIDFromWebmeshAddr returns the peer ID argument from a webmesh multiaddr.
func PeerIDFromWebmeshAddr(addr multiaddr.Multiaddr) (peer.ID, error) {
	pid, err := addr.ValueForProtocol(P_WEBMESH)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNoPeerID, err)
	}
	if pid == "" {
		return "", fmt.Errorf("%w: %s", ErrNoPeerID, addr)
	}
	parts := strings.Split(strings.TrimPrefix(pid, "/"), "/")
	if len(parts) < 1 || parts[0] == "" {
		return "", fmt.Errorf("%w: %s", ErrNoPeerID, addr)
	}
	// The ID is base58 encoded, so it's length is not fixed.
	decoded, err := peer.Decode(parts[0])
	if err != nil {
		return "", fmt.Errorf("%w: %w: %s", ErrNoPeerID, err, addr)
	}
	return peer.ID(decoded), nil
}

// RendezvousFromWebmeshAddr returns the rendezvous argument from a webmesh multiaddr.
func RendezvousFromWebmeshAddr(addr multiaddr.Multiaddr) (string, error) {
	rendezvous, err := addr.ValueForProtocol(P_WEBMESH)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNoRedezvous, err)
	}
	if rendezvous == "" {
		return "", fmt.Errorf("%w: %s", ErrNoRedezvous, addr)
	}
	parts := strings.Split(strings.TrimPrefix(rendezvous, "/"), "/")
	if len(parts) < 2 || parts[1] == "" {
		return "", fmt.Errorf("%w: %s", ErrNoRedezvous, addr)
	}
	return parts[1], nil
}

func protocolStrToBytes(s string) ([]byte, error) {
	return []byte(s), nil
}

func protocolBytesToStr(b []byte) (string, error) {
	return string(b), nil
}

func validateBytes(b []byte) error {
	return nil
}
