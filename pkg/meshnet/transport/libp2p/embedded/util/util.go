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

// Package util provides utility functions for the webmesh libp2p integrations.
package util

import (
	"fmt"
	"net"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/webmeshproj/webmesh/pkg/context"
	wmcrypto "github.com/webmeshproj/webmesh/pkg/crypto"
)

// ErrNotStarted is returned when the transport is not started.
var ErrNotStarted = fmt.Errorf("transport is not started")

// ErrInvalidSecureTransport is returned when the transport is not used with a webmesh keypair and security transport.
var ErrInvalidSecureTransport = fmt.Errorf("transport must be used with a webmesh keypair and security transport")

// ExtractWebmeshPublicKey extracts the webmesh public key from a peer ID.
func ExtractWebmeshPublicKey(ctx context.Context, p peer.ID) (wmcrypto.PublicKey, error) {
	log := context.LoggerFrom(ctx)
	key, err := p.ExtractPublicKey()
	if err != nil {
		log.Debug("Failed to extract public key from peer ID", "error", err.Error())
		return nil, fmt.Errorf("failed to extract public key from peer ID: %w", err)
	}
	wmkey, err := ToWebmeshPublicKey(key)
	if err != nil {
		log.Warn("Failed to convert public key to webmesh key", "error", err.Error())
		return nil, fmt.Errorf("failed to convert public key to webmesh key: %w", err)
	}
	return wmkey, nil
}

// ToWebmeshPublicKey converts a libp2p public key to a webmesh public key.
func ToWebmeshPublicKey(in crypto.PubKey) (wmcrypto.PublicKey, error) {
	var raw []byte
	pubKey, ok := in.(*crypto.Ed25519PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: invalid public key type: %T", ErrInvalidSecureTransport, in)
	}
	raw, _ = pubKey.Raw()
	// Pack the key into a webmesh key
	key, err := wmcrypto.ParsePublicKey(raw)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// ToWebmeshPrivateKey converts a libp2p private key to a webmesh private key.
func ToWebmeshPrivateKey(in crypto.PrivKey) (wmcrypto.PrivateKey, error) {
	var raw []byte
	privkey, ok := in.(*crypto.Ed25519PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: invalid private key type: %T", ErrInvalidSecureTransport, in)
	}
	raw, _ = privkey.Raw()
	// Pack the key into a webmesh key
	key, err := wmcrypto.ParsePrivateKey(raw)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// GetTransport returns the transport type of a connection.
func GetTransport(c net.Conn) (proto string) {
	switch c.(type) {
	case *net.TCPConn:
		proto = "tcp"
	case *net.UDPConn:
		proto = "udp"
	case *net.IPConn:
		proto = "ip"
	default:
		proto = "unknown"
	}
	return
}
