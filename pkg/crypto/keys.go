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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"sort"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	cryptopb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/proto"

	"github.com/webmeshproj/webmesh/pkg/util"
)

// WireGuardKeyType is the protobuf key type for WireGuard keys.
const WireGuardKeyType cryptopb.KeyType = 5

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

	// Encode returns the base64 encoded string representation of the marshaled key.
	Encode() (string, error)

	// Marshal returns the protobuf marshaled key.
	Marshal() ([]byte, error)

	// Rendezvous generates a rendezvous string for discovering the peers at the given
	// public wireguard keys.
	Rendezvous(keys ...PublicKey) string
}

// PrivateKey is a private key used for encryption and identity over libp2p
type PrivateKey interface {
	Key

	p2pcrypto.PrivKey

	// ToNativeIdentity marshals this key back and forth into a native
	// libp2p ed25519 identity. This is used for mesh discovery mechanisms
	// and is not compatible with the larger webmesh transport.
	ToNativeIdentity() (p2pcrypto.PrivKey, error)

	// PublicKey returns the PublicKey as a PublicKey interface.
	PublicKey() PublicKey
}

// PublicKey is a public key used for encryption and identity over libp2p
type PublicKey interface {
	Key

	p2pcrypto.PubKey

	// ToNativeIdentity marshals this key back and forth into a native
	// libp2p ed25519 identity. This is used for mesh discovery mechanisms
	// and is not compatible with the larger webmesh transport. This cannot
	// be called on truncated public keys.
	ToNativeIdentity() (p2pcrypto.PubKey, error)

	// IsTruncated returns true if this is a truncated public key.
	// A truncated public key has taken a round trip or three through
	// the libp2p libraries and has lost its ed25519 public key bytes.
	// Only the WireGuard key bytes remain.
	IsTruncated() bool
}

// GenerateKey generates a new private key.
func GenerateKey() (PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &WireGuardKey{
		native: priv,
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
	var key cryptopb.PrivateKey
	if err := proto.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}
	if key.Type == nil || *key.Type != WireGuardKeyType {
		return nil, fmt.Errorf("invalid private key type")
	}
	return ParsePrivateKey(key.Data)
}

// DecodePublicKey decodes a public key from a base64 encoded string.
func DecodePublicKey(s string) (PublicKey, error) {
	data, err := p2pcrypto.ConfigDecodeKey(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}
	var key cryptopb.PublicKey
	if err := proto.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}
	if key.Type == nil || *key.Type != WireGuardKeyType {
		return nil, fmt.Errorf("invalid public key type")
	}
	return ParsePublicKey(key.Data)
}

// ParsePrivateKey parses a private key from a byte slice.
func ParsePrivateKey(data []byte) (PrivateKey, error) {
	return &WireGuardKey{
		native: ed25519.PrivateKey(data),
	}, nil
}

// ParsePublicKey parses a public key from a byte slice.
func ParsePublicKey(data []byte) (PublicKey, error) {
	if len(data) < wgtypes.KeyLen {
		return nil, fmt.Errorf("invalid wireguard public key length")
	}
	if len(data) == wgtypes.KeyLen {
		// This key went through a round trip through the libp2p library.
		// We only have the wireguard key bytes, not the ec public key bytes.
		// Signature verification will not work.
		var key [wgtypes.KeyLen]byte
		copy(key[:], data)
		return &WireGuardPublicKey{
			wgkey: wgtypes.Key(key),
		}, nil
	}
	// We have the full key bytes.
	return &WireGuardPublicKey{
		native: ed25519.PublicKey(data[wgtypes.KeyLen:]),
		wgkey:  wgtypes.Key(data[:wgtypes.KeyLen]),
	}, nil
}

// WireGuardKey represents a private WireGuard key as a libp2p key.
type WireGuardKey struct {
	native ed25519.PrivateKey
}

// ToNativeIdentity returns the libp2p private key as a full ed25519
// identity. This is used for mesh discovery mechanisms and is not compatible
// with the larger webmesh transport.
func (w *WireGuardKey) ToNativeIdentity() (p2pcrypto.PrivKey, error) {
	// We marshal and unmarshal back.
	raw, err := w.Raw()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ed25519 private key: %w", err)
	}
	pb := cryptopb.PrivateKey{
		Type: util.Pointer(cryptopb.KeyType_Ed25519),
		Data: raw,
	}
	marshaled, err := proto.Marshal(&pb)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	return p2pcrypto.UnmarshalPrivateKey(marshaled)
}

// ID returns the peer ID corresponding to the key.
func (w *WireGuardKey) ID() peer.ID {
	return w.PublicKey().ID()
}

// Equals checks whether two PubKeys are the same
func (w *WireGuardKey) Equals(in p2pcrypto.Key) bool {
	if _, ok := in.(*WireGuardKey); !ok {
		return false
	}
	this, _ := w.Raw()
	out, _ := in.(*WireGuardKey).Raw()
	return subtle.ConstantTimeCompare(this[:], out[:]) == 1
}

// Raw returns the raw bytes of the key (not wrapped in the libp2p-crypto protobuf).
func (w *WireGuardKey) Raw() ([]byte, error) {
	buf := make([]byte, len(w.native))
	copy(buf, w.native)
	return buf, nil
}

// Type returns the protobuf key type.
func (w *WireGuardKey) Type() cryptopb.KeyType {
	return WireGuardKeyType
}

// Cryptographically sign the given bytes
func (w *WireGuardKey) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(w.native, data), nil
}

// Return a public key paired with this private key
func (w *WireGuardKey) GetPublic() p2pcrypto.PubKey {
	return &WireGuardPublicKey{
		native: w.native.Public().(ed25519.PublicKey),
		wgkey:  w.WireGuardKey().PublicKey(),
	}
}

// PublicKey returns the PublicKey as a PublicKey interface.
func (w *WireGuardKey) PublicKey() PublicKey {
	return w.GetPublic().(*WireGuardPublicKey)
}

// Marshal returns the protobuf marshaled key.
func (w *WireGuardKey) Marshal() ([]byte, error) {
	raw, err := w.Raw()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ed25519 private key: %w", err)
	}
	pb := cryptopb.PrivateKey{
		Type: util.Pointer(WireGuardKeyType),
		Data: raw,
	}
	marshaled, err := proto.Marshal(&pb)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	return marshaled, nil
}

// WireGuardKey returns the WireGuard key.
func (w *WireGuardKey) WireGuardKey() wgtypes.Key {
	var key [wgtypes.KeyLen]byte
	copy(key[:], w.native[wgtypes.KeyLen:])
	return wgtypes.Key(key)
}

// String returns the base64 encoded string representation of the key.
func (w *WireGuardKey) Encode() (string, error) {
	marshaled, err := w.Marshal()
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
	native ed25519.PublicKey
	wgkey  wgtypes.Key
}

// ToNativeIdentity returns the libp2p private key as a full ed25519
// identity. This is used for mesh discovery mechanisms and is not compatible
// with the larger webmesh transport.
func (w *WireGuardPublicKey) ToNativeIdentity() (p2pcrypto.PubKey, error) {
	// We marshal and unmarshal back.
	if w.IsTruncated() {
		return nil, fmt.Errorf("cannot convert truncated public key to native identity")
	}
	pb := cryptopb.PublicKey{
		Type: util.Pointer(cryptopb.KeyType_Ed25519),
		Data: w.native,
	}
	marshaled, err := proto.Marshal(&pb)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	return p2pcrypto.UnmarshalPublicKey(marshaled)
}

// ID returns the peer ID corresponding to the key.
// On private keys, this is the peer ID of the public key.
func (w *WireGuardPublicKey) ID() peer.ID {
	id, _ := peer.IDFromPublicKey(w)
	return id
}

// WireGuardKey returns the WireGuard key.
func (w *WireGuardPublicKey) WireGuardKey() wgtypes.Key {
	return w.wgkey
}

// Verify compares a signature against the input data
func (w *WireGuardPublicKey) Verify(data []byte, sig []byte) (success bool, err error) {
	if w.IsTruncated() {
		return false, fmt.Errorf("cannot verify signature with truncated public key")
	}
	return ed25519.Verify(w.native, data, sig), nil
}

// Type returns the protobuf key type.
func (w *WireGuardPublicKey) Type() cryptopb.KeyType {
	return WireGuardKeyType
}

// Raw returns the raw bytes of the key (not wrapped in the libp2p-crypto protobuf).
// We only return the public key bytes, not the wireguard key bytes.
func (w *WireGuardPublicKey) Raw() ([]byte, error) {
	// This function is called during the ID generation process.
	// Currently libp2p will not use an ID derevation algorithm
	// unless the raw data is capped at 42 bytes. So we'll just return
	// the bytes of the wireguard key and the first half of the ed25519 key.
	// This means that on certain round trips of the public key through the
	// libp2p library, you may lose the ec public key and be unable to verify signatures.
	data := make([]byte, wgtypes.KeyLen)
	copy(data, w.wgkey[:])
	return data, nil
}

// raw returns the actual raw data for use in encoding and marshaling.
func (w *WireGuardPublicKey) fullRaw() []byte {
	return append(w.wgkey[:], w.native...)
}

// IsTruncated returns true if this is a truncated public key.
// A truncated public key has taken a round trip or three through
// the libp2p libraries and has lost its ed25519 public key bytes.
// Only the WireGuard key bytes remain.
func (w *WireGuardPublicKey) IsTruncated() bool {
	return len(w.native) < ed25519.PublicKeySize
}

// Equals checks whether two PubKeys are the same
func (w *WireGuardPublicKey) Equals(in p2pcrypto.Key) bool {
	// We only check the wireguard keys match
	if _, ok := in.(*WireGuardPublicKey); !ok {
		return false
	}
	thisb := w.wgkey
	inb := in.(*WireGuardPublicKey).wgkey
	return bytes.Equal(thisb[:], inb[:])
}

// Marshal returns the protobuf marshaled key.
func (w *WireGuardPublicKey) Marshal() ([]byte, error) {
	// Proto marshal the key with the wireguard key type and the raw wireguard
	// public key appended to the top of the protobuf bytes.
	pb := cryptopb.PublicKey{
		Type: util.Pointer(WireGuardKeyType),
		Data: w.fullRaw(),
	}
	marshaled, err := proto.Marshal(&pb)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	return marshaled, nil
}

// Encode returns the base64 encoded string representation of the key.
func (w *WireGuardPublicKey) Encode() (string, error) {
	marshaled, err := w.Marshal()
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	return p2pcrypto.ConfigEncodeKey(marshaled), nil
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
