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

package transport

import (
	"fmt"
	"net"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/webmeshproj/webmesh/pkg/context"
	wmcrypto "github.com/webmeshproj/webmesh/pkg/crypto"
)

// ErrInvalidSecureTransport is returned when the transport is not used with a webmesh keypair and security transport.
var ErrInvalidSecureTransport = fmt.Errorf("transport must be used with a webmesh keypair and security transport")

func extractWebmeshPublicKey(ctx context.Context, p peer.ID) (wmcrypto.PublicKey, error) {
	log := context.LoggerFrom(ctx)
	key, err := p.ExtractPublicKey()
	if err != nil {
		log.Debug("Failed to extract public key from peer ID", "error", err.Error())
		return nil, fmt.Errorf("failed to extract public key from peer ID: %w", err)
	}
	wmkey, err := toWebmeshPublicKey(key)
	if err != nil {
		log.Warn("Failed to convert public key to webmesh key", "error", err.Error())
		return nil, fmt.Errorf("failed to convert public key to webmesh key: %w", err)
	}
	return wmkey, nil
}

func toWebmeshPublicKey(in crypto.PubKey) (wmcrypto.PublicKey, error) {
	if v, ok := in.(wmcrypto.PublicKey); ok {
		return v, nil
	}
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

func toWebmeshPrivateKey(in crypto.PrivKey) (wmcrypto.PrivateKey, error) {
	if v, ok := in.(wmcrypto.PrivateKey); ok {
		return v, nil
	}
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

func getTransport(c net.Conn) (proto string) {
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
