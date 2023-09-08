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
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/crypto/pb"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WireGuardKeyType is the protobuf key type for WireGuard keys.
const WireGuardKeyType pb.KeyType = 613

// Key is a cryptographic key.
type Key interface {
	p2pcrypto.Key

	// WireGuardKey returns the WireGuard key.
	WireGuardKey() wgtypes.Key

	// Encode returns the base64 encoded string representation of the key.
	Encode() (string, error)

	// Rendezvous generates a rendezvous string for discovering the peers at the given
	// public wireguard keys.
	Rendezvous(keys ...PublicKey) string
}

// PrivateKey is a private key used for encryption and identity over libp2p
type PrivateKey interface {
	Key
	p2pcrypto.PrivKey

	// PublicKey returns the PublicKey as a PublicKey interface.
	PublicKey() PublicKey

	// Native returns the native underlying secp256k1 key for use
	// with security libraries that require it.
	Native() p2pcrypto.PrivKey
}

// PublicKey is a public key used for encryption and identity over libp2p
type PublicKey interface {
	Key
	p2pcrypto.PubKey

	// Native returns the native underlying secp256k1 key for use
	// with security libraries that require it.
	Native() p2pcrypto.PubKey
}

func init() {
	p2pcrypto.PrivKeyUnmarshallers[WireGuardKeyType] = func(data []byte) (p2pcrypto.PrivKey, error) {
		return ParsePrivateKey(data)
	}
	p2pcrypto.PubKeyUnmarshallers[WireGuardKeyType] = func(data []byte) (p2pcrypto.PubKey, error) {
		return ParsePublicKey(data)
	}
	p2pcrypto.KeyTypes = append(p2pcrypto.KeyTypes, int(WireGuardKeyType.Number()))
}

// GenerateKey generates a new private key.
func GenerateKey() (PrivateKey, error) {
	priv, _, err := p2pcrypto.GenerateKeyPair(p2pcrypto.Secp256k1, 256)
	if err != nil {
		return nil, err
	}
	return &privateKey{ecdsa: priv.(*p2pcrypto.Secp256k1PrivateKey)}, nil
}

// MustGenerateKey generates a new private key or panics.
func MustGenerateKey() PrivateKey {
	priv, err := GenerateKey()
	if err != nil {
		panic(err)
	}
	return priv
}

// DecodePrivateKey decodes a private key from a base64 encoded string.
func DecodePrivateKey(s string) (PrivateKey, error) {
	data, err := p2pcrypto.ConfigDecodeKey(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}
	return ParsePrivateKey(data)
}

// ParsePrivateKey parses a private key from a byte slice.
func ParsePrivateKey(data []byte) (PrivateKey, error) {
	unmarshaled, err := p2pcrypto.UnmarshalPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal key: %w", err)
	}
	return &privateKey{ecdsa: unmarshaled.(*p2pcrypto.Secp256k1PrivateKey)}, nil
}

// DecodePublicKey decodes a public key from a base64 encoded string.
func DecodePublicKey(s string) (PublicKey, error) {
	data, err := p2pcrypto.ConfigDecodeKey(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}
	return ParsePublicKey(data)
}

// ParsePublicKey parses a public key from a byte slice.
func ParsePublicKey(data []byte) (PublicKey, error) {
	pub, err := p2pcrypto.UnmarshalPublicKey(data[wgtypes.KeyLen:])
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal secp256k1 public key: %w", err)
	}
	return &publicKey{
		ecdsa: pub.(*p2pcrypto.Secp256k1PublicKey),
		wgkey: wgtypes.Key(data[:wgtypes.KeyLen]),
	}, nil
}

type privateKey struct {
	ecdsa *p2pcrypto.Secp256k1PrivateKey
}

func (w *privateKey) Native() p2pcrypto.PrivKey {
	return w.ecdsa
}

// Equals checks whether two PubKeys are the same
func (w *privateKey) Equals(in p2pcrypto.Key) bool {
	if _, ok := in.(*privateKey); !ok {
		return false
	}
	this, _ := w.ecdsa.Raw()
	out, _ := in.(*privateKey).ecdsa.Raw()
	return bytes.Equal(this[:], out[:])
}

// Raw returns the raw bytes of the key (not wrapped in the libp2p-crypto protobuf).
func (w *privateKey) Raw() ([]byte, error) {
	return w.ecdsa.Raw()
}

// Type returns the protobuf key type.
func (w *privateKey) Type() pb.KeyType {
	return WireGuardKeyType
}

// Cryptographically sign the given bytes
func (w *privateKey) Sign(data []byte) ([]byte, error) {
	return w.ecdsa.Sign(data)
}

// Return a public key paired with this private key
func (w *privateKey) GetPublic() p2pcrypto.PubKey {
	return &publicKey{
		ecdsa: w.ecdsa.GetPublic().(*p2pcrypto.Secp256k1PublicKey),
		wgkey: w.WireGuardKey().PublicKey(),
	}
}

// PublicKey returns the PublicKey as a PublicKey interface.
func (w *privateKey) PublicKey() PublicKey {
	return w.GetPublic().(*publicKey)
}

// WireGuardKey returns the WireGuard key.
func (w *privateKey) WireGuardKey() wgtypes.Key {
	raw, _ := w.ecdsa.Raw()
	return wgtypes.Key(raw)
}

// String returns the base64 encoded string representation of the key.
func (w *privateKey) Encode() (string, error) {
	marshaled, err := p2pcrypto.MarshalPrivateKey(w.ecdsa)
	if err != nil {
		return "", fmt.Errorf("failed to marshal secp256k1 private key: %w", err)
	}
	return p2pcrypto.ConfigEncodeKey(marshaled), nil
}

// Rendezvous generates a rendezvous string for discovering the peers at the given
// public wireguard keys.
func (k *privateKey) Rendezvous(keys ...PublicKey) string {
	return k.PublicKey().Rendezvous(keys...)
}

type publicKey struct {
	ecdsa *p2pcrypto.Secp256k1PublicKey
	wgkey wgtypes.Key
}

func (w *publicKey) Native() p2pcrypto.PubKey {
	return w.ecdsa
}

// WireGuardKey returns the WireGuard key.
func (w *publicKey) WireGuardKey() wgtypes.Key {
	return w.wgkey
}

// Verify compares a signature against the input data
func (w *publicKey) Verify(data []byte, sigStr []byte) (success bool, err error) {
	return w.ecdsa.Verify(data, sigStr)
}

// Type returns the protobuf key type.
func (w *publicKey) Type() pb.KeyType {
	return WireGuardKeyType
}

// Raw returns the raw bytes of the key (not wrapped in the libp2p-crypto protobuf).
// We only return the public key bytes, not the wireguard key bytes.
func (w *publicKey) Raw() ([]byte, error) {
	marshaled, err := p2pcrypto.MarshalPublicKey(w.ecdsa)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal secp256k1 public key: %w", err)
	}
	return append(w.wgkey[:], marshaled...), nil
}

// Equals checks whether two PubKeys are the same
func (w *publicKey) Equals(in p2pcrypto.Key) bool {
	if _, ok := in.(*publicKey); !ok {
		return false
	}
	this := w.wgkey
	out := in.(*publicKey).wgkey
	return bytes.Equal(this[:], out[:])
}

// Encode returns the base64 encoded string representation of the key.
func (w *publicKey) Encode() (string, error) {
	raw, err := w.Raw()
	if err != nil {
		return "", err
	}
	return p2pcrypto.ConfigEncodeKey(raw), nil
}

// Rendezvous generates a rendezvous string for discovering the peers at the given
// public wireguard keys.
func (k *publicKey) Rendezvous(keys ...PublicKey) string {
	keys = append(keys, k)
	return Rendezvous(keys...)
}

// Rendezvous generates a rendezvous string for discovering the peers at the given
// public wireguard keys.
func Rendezvous(keys ...PublicKey) string {
	keyStrs := make([]string, len(keys))
	for i, key := range keys {
		keyStrs[i] = key.WireGuardKey().String()
	}
	sort.Strings(keyStrs)
	h := sha256.New()
	for _, k := range keyStrs {
		h.Write([]byte(k))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
