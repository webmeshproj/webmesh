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

// Package crypto contains cryptographic utilities.
package crypto

import (
	"crypto/rand"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Key is a private key used for encryption and identity over libp2p
// and WireGuard tunnels.
type Key interface {
	// PrivateKey returns the WireGuard private key derived from the
	// given key.
	PrivateKey() wgtypes.Key
	// PublicKey returns the public WireGuard key derived from the given key.
	PublicKey() wgtypes.Key
	// HostKey returns a libp2p compatible host key-pair.
	HostKey() p2pcrypto.PrivKey
	// PublicHostString returns the base64 encoded string representation of the full host public key.
	PublicHostString() string
	// String return the base64 encoded string representation of the key.
	String() string
}

type key struct {
	hostpriv      p2pcrypto.PrivKey
	raw           []byte
	marshaledPriv []byte
	marshaledPub  []byte
}

// MustGenerateKey generates a new private key or panics.
func MustGenerateKey() Key {
	k, err := GenerateKey()
	if err != nil {
		panic(err)
	}
	return k
}

// GenerateKey generates a new private key.
func GenerateKey() (Key, error) {
	priv, pub, err := p2pcrypto.GenerateKeyPairWithReader(p2pcrypto.ECDSA, 256, rand.Reader)
	if err != nil {
		return nil, err
	}
	marshaledPriv, err := p2pcrypto.MarshalPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	marshaledPub, err := p2pcrypto.MarshalPublicKey(pub)
	if err != nil {
		return nil, err
	}
	raw, err := priv.Raw()
	if err != nil {
		return nil, err
	}
	return &key{
		raw:           raw,
		hostpriv:      priv,
		marshaledPriv: marshaledPriv,
		marshaledPub:  marshaledPub,
	}, nil
}

// ParseKeyFromString parses the key from the given base64 encoded string.
func ParseKey(s string) (Key, error) {
	data, err := p2pcrypto.ConfigDecodeKey(s)
	if err != nil {
		return nil, err
	}
	return ParseKeyFromBytes(data)
}

// ParseHostPublicKey parses the host public key from the given base64 encoded string.
func ParseHostPublicKey(s string) (p2pcrypto.PubKey, error) {
	data, err := p2pcrypto.ConfigDecodeKey(s)
	if err != nil {
		return nil, err
	}
	return p2pcrypto.UnmarshalPublicKey(data)
}

// ParseKey parses a private key from the given bytes.
func ParseKeyFromBytes(data []byte) (Key, error) {
	priv, err := p2pcrypto.UnmarshalPrivateKey(data)
	if err != nil {
		return nil, err
	}
	privraw, err := priv.Raw()
	if err != nil {
		return nil, err
	}
	marshaledPub, err := p2pcrypto.MarshalPublicKey(priv.GetPublic())
	if err != nil {
		return nil, err
	}
	return &key{
		raw:           privraw,
		hostpriv:      priv,
		marshaledPriv: data,
		marshaledPub:  marshaledPub,
	}, nil
}

// PrivateKey returns the WireGuard private key derived from the
// given key.
func (k *key) PrivateKey() wgtypes.Key {
	return wgtypes.Key(k.raw)
}

// PublicKey returns the public WireGuard key derived from the given key.
func (k *key) PublicKey() wgtypes.Key {
	return k.PrivateKey().PublicKey()
}

// HostKey returns a libp2p compatible host key-pair.
func (k *key) HostKey() p2pcrypto.PrivKey {
	return k.hostpriv
}

// PublicHostString returns the base64 encoded string representation of the full host public key.
func (k *key) PublicHostString() string {
	return p2pcrypto.ConfigEncodeKey(k.marshaledPub)
}

// String return the base64 encoded string representation of the key.
func (k *key) String() string {
	return p2pcrypto.ConfigEncodeKey(k.marshaledPriv)
}
