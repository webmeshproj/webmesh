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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"

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
	// HostKeyPair returns a libp2p compatible host key-pair.
	HostKeyPair() (p2pcrypto.PrivKey, p2pcrypto.PubKey)
	// String return the base64 encoded string representation of the key.
	String() string
}

type key struct {
	priv      *ecdsa.PrivateKey
	wgkey     wgtypes.Key
	hostpriv  p2pcrypto.PrivKey
	hostpub   p2pcrypto.PubKey
	marshaled []byte
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
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	raw, err := priv.ECDH()
	if err != nil {
		return nil, err
	}
	hostpriv, hostpub, err := p2pcrypto.ECDSAKeyPairFromKey(priv)
	if err != nil {
		return nil, err
	}
	marshaled, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return &key{
		priv:      priv,
		wgkey:     wgtypes.Key(raw.Bytes()),
		hostpriv:  hostpriv,
		hostpub:   hostpub,
		marshaled: marshaled,
	}, nil
}

// ParseKeyFromString parses the key from the given base64 encoded string.
func ParseKey(s string) (Key, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return ParseKeyFromBytes(data)
}

// ParseKey parses a private key from the given bytes.
func ParseKeyFromBytes(data []byte) (Key, error) {
	priv, err := x509.ParseECPrivateKey(data)
	if err != nil {
		return nil, err
	}
	raw, err := priv.ECDH()
	if err != nil {
		return nil, err
	}
	hotspriv, hostpub, err := p2pcrypto.ECDSAKeyPairFromKey(priv)
	if err != nil {
		return nil, err
	}
	marshaled, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return &key{
		priv:      priv,
		wgkey:     wgtypes.Key(raw.Bytes()),
		hostpriv:  hotspriv,
		hostpub:   hostpub,
		marshaled: marshaled,
	}, nil
}

// PrivateKey returns the WireGuard private key derived from the
// given key.
func (k *key) PrivateKey() wgtypes.Key {
	return k.wgkey
}

// PublicKey returns the public WireGuard key derived from the given key.
func (k *key) PublicKey() wgtypes.Key {
	return k.wgkey.PublicKey()
}

// HostKey returns a libp2p compatible host key-pair.
func (k *key) HostKeyPair() (p2pcrypto.PrivKey, p2pcrypto.PubKey) {
	return k.hostpriv, k.hostpub
}

// String return the base64 encoded string representation of the key.
func (k *key) String() string {
	return base64.StdEncoding.EncodeToString(k.marshaled)
}
