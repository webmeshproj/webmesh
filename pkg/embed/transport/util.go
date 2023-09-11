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

	pcrypto "github.com/libp2p/go-libp2p/core/crypto"

	"github.com/webmeshproj/webmesh/pkg/crypto"
)

// ErrInvalidSecureTransport is returned when the transport is not used with a webmesh keypair and security transport.
var ErrInvalidSecureTransport = fmt.Errorf("transport must be used with a webmesh keypair and security transport")

func toWebmeshPrivateKey(in pcrypto.PrivKey) (crypto.PrivateKey, error) {
	if v, ok := in.(crypto.PrivateKey); ok {
		return v, nil
	}
	var raw []byte
	privkey, ok := in.(*pcrypto.Ed25519PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: invalid private key type: %T", ErrInvalidSecureTransport, in)
	}
	raw, _ = privkey.Raw()
	// Pack the key into a webmesh key
	key, err := crypto.ParsePrivateKey(raw)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func toWebmeshPublicKey(in pcrypto.PubKey) (crypto.PublicKey, error) {
	if v, ok := in.(crypto.PublicKey); ok {
		return v, nil
	}
	var raw []byte
	privkey, ok := in.(*pcrypto.Ed25519PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: invalid private key type: %T", ErrInvalidSecureTransport, in)
	}
	raw, _ = privkey.Raw()
	// Pack the key into a webmesh key
	key, err := crypto.ParsePublicKey(raw)
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
