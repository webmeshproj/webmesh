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
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"sort"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	cryptopb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/peer"
	mh "github.com/multiformats/go-multihash"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WireGuardKeyType is the protobuf key type for WireGuard keys.
const WireGuardKeyType cryptopb.KeyType = 613

func init() {
	cryptopb.KeyType_name[int32(WireGuardKeyType)] = "WireGuard"
	cryptopb.KeyType_value["WireGuard"] = int32(WireGuardKeyType)
	p2pcrypto.KeyTypes = append(p2pcrypto.KeyTypes, int(WireGuardKeyType.Number()))
	p2pcrypto.PrivKeyUnmarshallers[WireGuardKeyType] = func(data []byte) (p2pcrypto.PrivKey, error) {
		return ParsePrivateKey(data)
	}
	p2pcrypto.PubKeyUnmarshallers[WireGuardKeyType] = func(data []byte) (p2pcrypto.PubKey, error) {
		return ParsePublicKey(data)
	}
}

// Key is the interface that all keys satisfy.
type Key interface {
	p2pcrypto.Key

	// ID returns the peer ID corresponding to the key.
	// On private keys, this is the peer ID of the public key.
	ID() peer.ID

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

	// Native returns the native private key.
	Native() p2pcrypto.PrivKey
}

// PublicKey is a public key used for encryption and identity over libp2p
type PublicKey interface {
	Key

	p2pcrypto.PubKey

	// Native returns the native public key.
	Native() p2pcrypto.PubKey
}

// GenerateKey generates a new private key.
func GenerateKey() (PrivateKey, error) {
	priv, _, err := p2pcrypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &WireGuardKey{
		native: priv.(*p2pcrypto.Ed25519PrivateKey),
	}, nil
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

func IDMatchesPublicKey(id peer.ID, key PublicKey) (bool, error) {
	extraced, err := ExtractPublicKeyFromID(id)
	if err != nil {
		return false, err
	}
	return key.Equals(extraced), nil
}

// ExtractPublicKeyFromID extracts the public key from the given peer ID.
func ExtractPublicKeyFromID(id peer.ID) (PublicKey, error) {
	decoded, err := mh.Decode([]byte(id))
	if err != nil {
		return nil, fmt.Errorf("failed to decode peer ID: %w", err)
	}
	if decoded.Code != mh.IDENTITY {
		return nil, fmt.Errorf("peer ID is not an identity hash")
	}
	return ParsePublicKey(decoded.Digest)
}

// DecodePublicKey decodes a public key from a base64 encoded string.
func DecodePublicKey(s string) (PublicKey, error) {
	data, err := p2pcrypto.ConfigDecodeKey(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}
	return ParsePublicKey(data)
}

// ParsePrivateKey parses a private key from a byte slice.
func ParsePrivateKey(data []byte) (PrivateKey, error) {
	unmarshaled, err := p2pcrypto.UnmarshalPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal key: %w", err)
	}
	return &WireGuardKey{
		native: unmarshaled.(*p2pcrypto.Ed25519PrivateKey),
	}, nil
}

// ParsePublicKey parses a public key from a byte slice.
func ParsePublicKey(data []byte) (PublicKey, error) {
	pub, err := p2pcrypto.UnmarshalPublicKey(data[wgtypes.KeyLen:])
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal secp256k1 public key: %w", err)
	}
	return &WireGuardPublicKey{
		native: pub.(*p2pcrypto.Ed25519PublicKey),
		wgkey:  wgtypes.Key(data[:wgtypes.KeyLen]),
	}, nil
}

// WireGuardKey represents a private WireGuard key as a libp2p key.
type WireGuardKey struct {
	native *p2pcrypto.Ed25519PrivateKey
}

func (w *WireGuardKey) Native() p2pcrypto.PrivKey {
	return w.native
}

func (w *WireGuardKey) ID() peer.ID {
	return w.PublicKey().ID()
}

// Equals checks whether two PubKeys are the same
func (w *WireGuardKey) Equals(in p2pcrypto.Key) bool {
	if _, ok := in.(*WireGuardKey); !ok {
		return false
	}
	this, _ := w.native.Raw()
	out, _ := in.(*WireGuardKey).native.Raw()
	return bytes.Equal(this[:], out[:])
}

// Raw returns the raw bytes of the key (not wrapped in the libp2p-crypto protobuf).
func (w *WireGuardKey) Raw() ([]byte, error) {
	return w.native.Raw()
}

// Type returns the protobuf key type.
func (w *WireGuardKey) Type() cryptopb.KeyType {
	return WireGuardKeyType
}

// Cryptographically sign the given bytes
func (w *WireGuardKey) Sign(data []byte) ([]byte, error) {
	return w.native.Sign(data)
}

// Return a public key paired with this private key
func (w *WireGuardKey) GetPublic() p2pcrypto.PubKey {
	return &WireGuardPublicKey{
		native: w.native.GetPublic().(*p2pcrypto.Ed25519PublicKey),
		wgkey:  w.WireGuardKey().PublicKey(),
	}
}

// PublicKey returns the PublicKey as a PublicKey interface.
func (w *WireGuardKey) PublicKey() PublicKey {
	return w.GetPublic().(*WireGuardPublicKey)
}

// WireGuardKey returns the WireGuard key.
func (w *WireGuardKey) WireGuardKey() wgtypes.Key {
	raw, _ := w.native.Raw()
	return wgtypes.Key(raw)
}

// String returns the base64 encoded string representation of the key.
func (w *WireGuardKey) Encode() (string, error) {
	marshaled, err := p2pcrypto.MarshalPrivateKey(w.native)
	if err != nil {
		return "", fmt.Errorf("failed to marshal secp256k1 private key: %w", err)
	}
	return p2pcrypto.ConfigEncodeKey(marshaled), nil
}

// Rendezvous generates a rendezvous string for discovering the peers at the given
// public wireguard keys.
func (k *WireGuardKey) Rendezvous(keys ...PublicKey) string {
	return k.PublicKey().Rendezvous(keys...)
}

// WireGuardPublicKey represents a public WireGuard key as a libp2p key.
type WireGuardPublicKey struct {
	native *p2pcrypto.Ed25519PublicKey
	wgkey  wgtypes.Key
}

func (w *WireGuardPublicKey) Native() p2pcrypto.PubKey {
	return w.native
}

// WireGuardKey returns the WireGuard key.
func (w *WireGuardPublicKey) WireGuardKey() wgtypes.Key {
	return w.wgkey
}

// Verify compares a signature against the input data
func (w *WireGuardPublicKey) Verify(data []byte, sigStr []byte) (success bool, err error) {
	return w.native.Verify(data, sigStr)
}

// Type returns the protobuf key type.
func (w *WireGuardPublicKey) Type() cryptopb.KeyType {
	return WireGuardKeyType
}

// Raw returns the raw bytes of the key (not wrapped in the libp2p-crypto protobuf).
// We only return the public key bytes, not the wireguard key bytes.
func (w *WireGuardPublicKey) Raw() ([]byte, error) {
	marshaled, err := p2pcrypto.MarshalPublicKey(w.native)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal secp256k1 public key: %w", err)
	}
	return append(w.wgkey[:], marshaled...), nil
}

// Equals checks whether two PubKeys are the same
func (w *WireGuardPublicKey) Equals(in p2pcrypto.Key) bool {
	if _, ok := in.(*WireGuardPublicKey); !ok {
		return false
	}
	this := w.wgkey
	out := in.(*WireGuardPublicKey).wgkey
	return bytes.Equal(this[:], out[:])
}

// Encode returns the base64 encoded string representation of the key.
func (w *WireGuardPublicKey) Encode() (string, error) {
	raw, err := w.Raw()
	if err != nil {
		return "", err
	}
	return p2pcrypto.ConfigEncodeKey(raw), nil
}

// ID returns the peer ID corresponding to the key.
// On private keys, this is the peer ID of the public key.
func (w *WireGuardPublicKey) ID() peer.ID {
	raw, err := w.Raw()
	if err != nil {
		panic(err)
	}
	hash, err := mh.Sum(raw, mh.IDENTITY, -1)
	if err != nil {
		panic(err)
	}
	return peer.ID(hash)
}

// Rendezvous generates a rendezvous string for discovering the peers at the given
// public wireguard keys.
func (k *WireGuardPublicKey) Rendezvous(keys ...PublicKey) string {
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
