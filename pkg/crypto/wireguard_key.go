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
	"crypto/sha256"
	"fmt"
	"sort"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	cryptopb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/peer"
	mh "github.com/multiformats/go-multihash"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/proto"

	"github.com/webmeshproj/webmesh/pkg/util"
)

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

// WireGuardKey represents a private WireGuard key as a libp2p key.
type WireGuardKey struct {
	ed25519 *p2pcrypto.Ed25519PrivateKey
	wgkey   wgtypes.Key
}

// WireGuardPublicKey represents a public WireGuard key as a libp2p key.
type WireGuardPublicKey struct {
	ed25519 *p2pcrypto.Ed25519PublicKey
	wgkey   wgtypes.Key
}

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

// GenerateKey generates a new private key.
func GenerateKey() (PrivateKey, error) {
	priv, _, err := p2pcrypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate wireguard private key: %w", err)
	}
	raw, err := priv.Raw()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw private key: %w", err)
	}
	return WireGuardKey{
		ed25519: priv.(*p2pcrypto.Ed25519PrivateKey),
		wgkey:   wgtypes.Key(raw),
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

// DecodePublicKey decodes a public key from a base64 encoded string.
func DecodePublicKey(s string) (PublicKey, error) {
	data, err := p2pcrypto.ConfigDecodeKey(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}
	return ParsePublicKey(data)
}

// ParsePrivateKey parses a private key from a protobuf serialized byte slice.
func ParsePrivateKey(data []byte) (PrivateKey, error) {
	key, err := p2pcrypto.UnmarshalPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal key: %w", err)
	}
	ed25519, ok := key.(*p2pcrypto.Ed25519PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an ed25519 key")
	}
	raw, err := ed25519.Raw()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw private key: %w", err)
	}
	return WireGuardKey{
		ed25519: ed25519,
		wgkey:   wgtypes.Key(raw),
	}, nil
}

// ParsePublicKey parses a public key from a protobuf serialized byte slice.
func ParsePublicKey(data []byte) (PublicKey, error) {
	pmes := new(cryptopb.PublicKey)
	err := proto.Unmarshal(data, pmes)
	if err != nil {
		return nil, err
	}
	var wgkey wgtypes.Key
	if len(pmes.Data) < wgtypes.KeyLen {
		return nil, fmt.Errorf("invalid key length")
	}
	copy(wgkey[:], pmes.Data[:wgtypes.KeyLen])
	key, err := p2pcrypto.UnmarshalPublicKey(pmes.Data[wgtypes.KeyLen:])
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal key: %w", err)
	}
	ed25519, ok := key.(*p2pcrypto.Ed25519PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an ed25519 key")
	}
	return WireGuardPublicKey{
		ed25519: ed25519,
		wgkey:   wgkey,
	}, nil
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
	var wgkey wgtypes.Key
	if len(decoded.Digest) < wgtypes.KeyLen {
		return nil, fmt.Errorf("invalid key length")
	}
	copy(wgkey[:], decoded.Digest[:wgtypes.KeyLen])
	decoded.Digest = decoded.Digest[wgtypes.KeyLen:]
	// Take the raw ed25519 key out of the remaining bytes
	ed25519, err := p2pcrypto.UnmarshalPublicKey(decoded.Digest)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ed25519 public key: %w", err)
	}
	key, ok := ed25519.(*p2pcrypto.Ed25519PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an ed25519 key")
	}
	return WireGuardPublicKey{
		ed25519: key,
		wgkey:   wgkey,
	}, nil
}

// Native returns the native private key.
func (w WireGuardKey) Native() p2pcrypto.PrivKey {
	return w.ed25519
}

// ID returns the peer ID corresponding to the key.
// On private keys, this is the peer ID of the public key.
func (w WireGuardKey) ID() peer.ID {
	return w.PublicKey().ID()
}

// WireGuardKey returns the WireGuard key.
func (w WireGuardKey) WireGuardKey() wgtypes.Key {
	return w.wgkey
}

// Equals checks whether two private keys are the same
func (w WireGuardKey) Equals(in p2pcrypto.Key) bool {
	inkey, ok := in.(WireGuardKey)
	if !ok {
		return false
	}
	return w.ed25519.Equals(inkey.ed25519)
}

// Raw returns the raw bytes of the key (not wrapped in the libp2p-crypto protobuf).
func (w WireGuardKey) Raw() ([]byte, error) {
	return w.ed25519.Raw()
}

// Type returns the protobuf key type.
func (w WireGuardKey) Type() cryptopb.KeyType {
	return WireGuardKeyType
}

// Cryptographically sign the given bytes
func (w WireGuardKey) Sign(data []byte) ([]byte, error) {
	return w.ed25519.Sign(data)
}

// Return a public key paired with this private key
func (w WireGuardKey) GetPublic() p2pcrypto.PubKey {
	return WireGuardPublicKey{
		ed25519: w.ed25519.GetPublic().(*p2pcrypto.Ed25519PublicKey),
		wgkey:   w.wgkey.PublicKey(),
	}
}

// PublicKey returns the PublicKey as a PublicKey interface.
func (w WireGuardKey) PublicKey() PublicKey {
	return w.GetPublic().(PublicKey)
}

// String returns the base64 encoded string representation of the key.
func (w WireGuardKey) Encode() (string, error) {
	data, err := p2pcrypto.MarshalPrivateKey(w.ed25519)
	if err != nil {
		return "", err
	}
	return p2pcrypto.ConfigEncodeKey(data), nil
}

// Rendezvous generates a rendezvous string for discovering the peers at the given
// public wireguard keys.
func (k WireGuardKey) Rendezvous(keys ...PublicKey) string {
	return k.PublicKey().Rendezvous(keys...)
}

// Native returns the native private key.
func (w WireGuardPublicKey) Native() p2pcrypto.PubKey {
	return w.ed25519
}

// ID returns the peer ID corresponding to the key.
// On private keys, this is the peer ID of the public key.
func (w WireGuardPublicKey) ID() peer.ID {
	marshaled, err := p2pcrypto.MarshalPublicKey(w.ed25519)
	if err != nil {
		panic(err)
	}
	data := append(w.wgkey[:], marshaled...)
	hash, err := mh.Sum(data, mh.IDENTITY, -1)
	if err != nil {
		panic(err)
	}
	return peer.ID(hash)
}

// WireGuardKey returns the WireGuard key.
func (w WireGuardPublicKey) WireGuardKey() wgtypes.Key {
	return w.wgkey
}

// Verify compares a signature against the input data
func (w WireGuardPublicKey) Verify(data []byte, sigStr []byte) (success bool, err error) {
	return w.ed25519.Verify(data, sigStr)
}

// Type returns the protobuf key type.
func (w WireGuardPublicKey) Type() cryptopb.KeyType {
	return WireGuardKeyType
}

// Raw returns the raw bytes of the key (not wrapped in the libp2p-crypto protobuf).
// We only return the public key bytes, not the wireguard key bytes.
func (w WireGuardPublicKey) Raw() ([]byte, error) {
	// We take the raw ed25519 key and append the wireguard key to it
	// This is because the wireguard key is not part of the libp2p-crypto protobuf
	// and we need to be able to get it back out
	raw, err := w.ed25519.Raw()
	if err != nil {
		return nil, err
	}
	return append(w.wgkey[:], raw...), nil
}

// Equals checks whether two PubKeys are the same
func (w WireGuardPublicKey) Equals(in p2pcrypto.Key) bool {
	inkey, ok := in.(WireGuardPublicKey)
	if !ok {
		return false
	}
	return w.ed25519.Equals(inkey.ed25519)
}

// Encode returns the base64 encoded string representation of the key.
func (w WireGuardPublicKey) Encode() (string, error) {
	marshaled, err := p2pcrypto.MarshalPublicKey(w.ed25519)
	if err != nil {
		return "", fmt.Errorf("failed to marshal ed25519 public key: %w", err)
	}
	data := cryptopb.PublicKey{
		Type: util.Pointer(WireGuardKeyType),
		Data: append(w.wgkey[:], marshaled...),
	}
	bytes, err := proto.Marshal(&data)
	if err != nil {
		return "", err
	}
	return p2pcrypto.ConfigEncodeKey(bytes), nil
}

// Rendezvous generates a rendezvous string for discovering the peers at the given
// public wireguard keys.
func (k WireGuardPublicKey) Rendezvous(keys ...PublicKey) string {
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
