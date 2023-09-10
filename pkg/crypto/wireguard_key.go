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
	cryptopb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/peer"
	mh "github.com/multiformats/go-multihash"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/proto"

	"github.com/webmeshproj/webmesh/pkg/util"
)

// WireGuardKey represents a private WireGuard key as a libp2p key.
type WireGuardKey wgtypes.Key

// WireGuardPublicKey represents a public WireGuard key as a libp2p key.
type WireGuardPublicKey wgtypes.Key

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
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate wireguard private key: %w", err)
	}
	return WireGuardKey(key), nil
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
	pmes := new(cryptopb.PrivateKey)
	err := proto.Unmarshal(data, pmes)
	if err != nil {
		return nil, err
	}
	return WireGuardKey(pmes.GetData()), nil
}

// ParsePublicKey parses a public key from a protobuf serialized byte slice.
func ParsePublicKey(data []byte) (PublicKey, error) {
	pmes := new(cryptopb.PublicKey)
	err := proto.Unmarshal(data, pmes)
	if err != nil {
		return nil, err
	}
	return WireGuardPublicKey(pmes.GetData()), nil
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
	return WireGuardPublicKey(decoded.Digest), nil
}

// Native returns the native private key.
func (w WireGuardKey) Native() p2pcrypto.PrivKey {
	return w
}

// ID returns the peer ID corresponding to the key.
// On private keys, this is the peer ID of the public key.
func (w WireGuardKey) ID() peer.ID {
	return w.PublicKey().ID()
}

// WireGuardKey returns the WireGuard key.
func (w WireGuardKey) WireGuardKey() wgtypes.Key {
	return wgtypes.Key(w[:])
}

// Equals checks whether two PubKeys are the same
func (w WireGuardKey) Equals(in p2pcrypto.Key) bool {
	inbytes, ok := in.(WireGuardKey)
	if !ok {
		return false
	}
	return bytes.Equal(w[:], inbytes[:])
}

// Raw returns the raw bytes of the key (not wrapped in the libp2p-crypto protobuf).
func (w WireGuardKey) Raw() ([]byte, error) {
	return w[:], nil
}

// Type returns the protobuf key type.
func (w WireGuardKey) Type() cryptopb.KeyType {
	return WireGuardKeyType
}

// Cryptographically sign the given bytes
func (w WireGuardKey) Sign(data []byte) ([]byte, error) {
	// No-op
	return []byte(WireGuardKeyType.String()), nil
}

// Return a public key paired with this private key
func (w WireGuardKey) GetPublic() p2pcrypto.PubKey {
	key := wgtypes.Key(w[:]).PublicKey()
	return WireGuardPublicKey(key)
}

// PublicKey returns the PublicKey as a PublicKey interface.
func (w WireGuardKey) PublicKey() PublicKey {
	return w.GetPublic().(PublicKey)
}

// String returns the base64 encoded string representation of the key.
func (w WireGuardKey) Encode() (string, error) {
	data := cryptopb.PrivateKey{
		Type: util.Pointer(WireGuardKeyType),
		Data: w[:],
	}
	bytes, err := proto.Marshal(&data)
	if err != nil {
		return "", err
	}
	return p2pcrypto.ConfigEncodeKey(bytes), nil
}

// Rendezvous generates a rendezvous string for discovering the peers at the given
// public wireguard keys.
func (k WireGuardKey) Rendezvous(keys ...PublicKey) string {
	return k.PublicKey().Rendezvous(keys...)
}

// Native returns the native private key.
func (w WireGuardPublicKey) Native() p2pcrypto.PubKey {
	return w
}

// ID returns the peer ID corresponding to the key.
// On private keys, this is the peer ID of the public key.
func (w WireGuardPublicKey) ID() peer.ID {
	hash, err := mh.Sum(w[:], mh.IDENTITY, -1)
	if err != nil {
		panic(err)
	}
	return peer.ID(hash)
}

// WireGuardKey returns the WireGuard key.
func (w WireGuardPublicKey) WireGuardKey() wgtypes.Key {
	return wgtypes.Key(w[:])
}

// Verify compares a signature against the input data
func (w WireGuardPublicKey) Verify(data []byte, sigStr []byte) (success bool, err error) {
	// No-op
	return true, nil
}

// Type returns the protobuf key type.
func (w WireGuardPublicKey) Type() cryptopb.KeyType {
	return WireGuardKeyType
}

// Raw returns the raw bytes of the key (not wrapped in the libp2p-crypto protobuf).
// We only return the public key bytes, not the wireguard key bytes.
func (w WireGuardPublicKey) Raw() ([]byte, error) {
	return w[:], nil
}

// Equals checks whether two PubKeys are the same
func (w WireGuardPublicKey) Equals(in p2pcrypto.Key) bool {
	keybytes, ok := in.(WireGuardPublicKey)
	if !ok {
		return false
	}
	return bytes.Equal(w[:], keybytes[:])
}

// Encode returns the base64 encoded string representation of the key.
func (w WireGuardPublicKey) Encode() (string, error) {
	data := cryptopb.PublicKey{
		Type: util.Pointer(WireGuardKeyType),
		Data: w[:],
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
