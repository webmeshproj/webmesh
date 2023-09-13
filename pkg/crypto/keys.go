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

package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"sort"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	cryptopb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/peer"
	oed25519 "github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/proto"

	"github.com/webmeshproj/webmesh/pkg/util"
)

// WebmeshKeyType is the protobuf key type for Webmesh keys.
const WebmeshKeyType cryptopb.KeyType = 5

func init() {
	cryptopb.KeyType_name[int32(WebmeshKeyType)] = "Webmesh"
	cryptopb.KeyType_value["Webmesh"] = int32(WebmeshKeyType)
	p2pcrypto.KeyTypes = append(p2pcrypto.KeyTypes, int(WebmeshKeyType))
	p2pcrypto.PrivKeyUnmarshallers[WebmeshKeyType] = func(data []byte) (p2pcrypto.PrivKey, error) {
		return ParsePrivateKey(data)
	}
	p2pcrypto.PubKeyUnmarshallers[WebmeshKeyType] = func(data []byte) (p2pcrypto.PubKey, error) {
		return ParsePublicKey(data)
	}
}

// Key is the interface that all keys satisfy.
type Key interface {
	p2pcrypto.Key

	// Bytes returns the raw bytes of the key. This is the same as Key.Raw
	// without needing to do an error check.
	Bytes() []byte

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

	// AsPrivKey returns the private key as a libp2p crypto private key.
	// This changes the type of the key to a ed25519 private key.
	AsPrivKey() p2pcrypto.PrivKey

	// PublicKey returns the PublicKey as a PublicKey interface.
	PublicKey() PublicKey
}

// PublicKey is a public key used for encryption and identity over libp2p
type PublicKey interface {
	Key
	p2pcrypto.PubKey
}

// GenerateKey generates a new private key.
func GenerateKey() (PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var raw [64]byte
	copy(raw[:], priv)
	return &WebmeshPrivateKey{
		raw: raw,
		typ: WebmeshKeyType,
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

// DecodePrivateKey decodes a private key from a base64 string.
func DecodePrivateKey(in string) (PrivateKey, error) {
	raw, err := p2pcrypto.ConfigDecodeKey(in)
	if err != nil {
		return nil, err
	}
	return UnmarshalPrivateKey(raw)
}

// DecodePublicKey decodes a public key from a base64 encoded string.
func DecodePublicKey(in string) (PublicKey, error) {
	raw, err := p2pcrypto.ConfigDecodeKey(in)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}
	return UnmarshalPublicKey(raw)
}

// UnmarshalPrivateKey unmarshals a private key from protobuf-serialized form.
func UnmarshalPrivateKey(data []byte) (PrivateKey, error) {
	var key cryptopb.PrivateKey
	if err := proto.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}
	if key.Type == nil || *key.Type != WebmeshKeyType {
		return nil, fmt.Errorf("invalid private key type")
	}
	return ParsePrivateKey(key.Data)
}

// UnmarshalPublicKey unmarshals a public key from protobuf-serialized form.
func UnmarshalPublicKey(data []byte) (PublicKey, error) {
	var key cryptopb.PublicKey
	if err := proto.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}
	if key.Type == nil || *key.Type != WebmeshKeyType {
		return nil, fmt.Errorf("invalid private key type")
	}
	return ParsePublicKey(key.Data)
}

// ParsePrivateKey parses a private key from raw protobuf-serialized form.
func ParsePrivateKey(data []byte) (PrivateKey, error) {
	if len(data) != 64 {
		return nil, fmt.Errorf("invalid private key length: %d", len(data))
	}
	var raw [64]byte
	copy(raw[:], data)
	return &WebmeshPrivateKey{
		raw: raw,
		typ: WebmeshKeyType,
	}, nil
}

// ParsePublicKey parses a public key from raw bytes.
func ParsePublicKey(data []byte) (PublicKey, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("invalid public key length: %d", len(data))
	}
	var raw [32]byte
	copy(raw[:], data)
	return &WebmeshPublicKey{
		raw: raw,
		typ: WebmeshKeyType,
	}, nil
}

// WebmeshPrivateKey is a private key used for webmesh transport.
type WebmeshPrivateKey struct {
	raw [64]byte
	typ cryptopb.KeyType
}

// AsPrivKey returns the private key as a libp2p crypto private key.
// This changes the type of the key to a ed25519 private key.
func (w *WebmeshPrivateKey) AsPrivKey() p2pcrypto.PrivKey {
	// We marshal the key back and forth assuming it was
	// already validated.
	raw, _ := w.Raw()
	ed25519, _ := p2pcrypto.UnmarshalEd25519PrivateKey(raw)
	return ed25519
}

// Type returns the protobuf key type.
func (w *WebmeshPrivateKey) Type() cryptopb.KeyType {
	return w.typ
}

// Bytes returns the raw bytes of the key. This is the same as Key.Raw
// without needing to do an error check.
func (w *WebmeshPrivateKey) Bytes() []byte {
	r, _ := w.Raw()
	return r
}

// Raw returns the raw bytes of the private key.
func (w *WebmeshPrivateKey) Raw() ([]byte, error) {
	out := make([]byte, 64)
	copy(out, w.raw[:])
	return out, nil
}

// Equals returns true if the given key is equal to this key.
func (w *WebmeshPrivateKey) Equals(inKey p2pcrypto.Key) bool {
	in, ok := inKey.(*WebmeshPrivateKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(w.raw[:], in.raw[:]) == 1
}

// Sign cryptographically signs the given bytes.
func (w *WebmeshPrivateKey) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(w.raw[:], data), nil
}

// Return a public key paired with this private key
func (w *WebmeshPrivateKey) GetPublic() p2pcrypto.PubKey {
	var out [32]byte
	copy(out[:], w.raw[32:])
	return &WebmeshPublicKey{raw: out, typ: WebmeshKeyType}
}

// PublicKey returns the public key.
func (w *WebmeshPrivateKey) PublicKey() PublicKey {
	return w.GetPublic().(PublicKey)
}

// WireGuardKey computes the private key's wireguard key.
func (w *WebmeshPrivateKey) WireGuardKey() wgtypes.Key {
	key := oed25519.PrivateKey(w.raw[:])
	wgkey := x25519.EdPrivateKeyToX25519(key)
	return wgtypes.Key(wgkey)
}

// Rendezvous generates a rendezvous string for discovering the peers at the given
// public wireguard keys.
func (k *WebmeshPrivateKey) Rendezvous(keys ...PublicKey) string {
	return k.PublicKey().Rendezvous(keys...)
}

// Encode returns the base64 encoded string representation of the marshaled key.
func (w *WebmeshPrivateKey) Encode() (string, error) {
	raw, err := w.Marshal()
	if err != nil {
		return "", err
	}
	return p2pcrypto.ConfigEncodeKey(raw), nil
}

// Marshal returns the protobuf marshaled key.
func (w *WebmeshPrivateKey) Marshal() ([]byte, error) {
	raw, _ := w.Raw()
	pb := cryptopb.PrivateKey{
		Type: util.Pointer(WebmeshKeyType),
		Data: raw,
	}
	marshaled, err := proto.Marshal(&pb)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	return marshaled, nil
}

// WebmeshPublicKey is a public key used for webmesh transport.
type WebmeshPublicKey struct {
	raw [32]byte
	typ cryptopb.KeyType
}

// ID returns the peer ID computed from the public key.
func (w *WebmeshPublicKey) ID() peer.ID {
	id, _ := peer.IDFromPublicKey(w)
	return id
}

// Type returns the protobuf key type.
func (w *WebmeshPublicKey) Type() cryptopb.KeyType {
	return w.typ
}

// Bytes returns the raw bytes of the key. This is the same as Key.Raw
// without needing to do an error check.
func (w *WebmeshPublicKey) Bytes() []byte {
	r, _ := w.Raw()
	return r
}

// Raw returns the raw bytes of the private key.
func (w *WebmeshPublicKey) Raw() ([]byte, error) {
	out := make([]byte, 32)
	copy(out, w.raw[:])
	return out, nil
}

func (w *WebmeshPublicKey) Equals(in p2pcrypto.Key) bool {
	inKey, ok := in.(*WebmeshPublicKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(w.raw[:], inKey.raw[:]) == 1
}

// Verify compares a signature against the input data
func (w *WebmeshPublicKey) Verify(data []byte, sig []byte) (success bool, err error) {
	return ed25519.Verify(w.raw[:], data, sig), nil
}

// WireGuardKey computes the private key's wireguard key.
func (w *WebmeshPublicKey) WireGuardKey() wgtypes.Key {
	key := oed25519.PublicKey(w.raw[:])
	wgkey, ok := x25519.EdPublicKeyToX25519(key)
	if !ok {
		panic("WireGuardKey called on invalid ed25519 public key")
	}
	return wgtypes.Key(wgkey)
}

// Rendezvous generates a rendezvous string for discovering the peers at the given
// public wireguard keys.
func (k *WebmeshPublicKey) Rendezvous(keys ...PublicKey) string {
	keys = append(keys, k)
	return Rendezvous(keys...)
}

// Encode returns the base64 encoded string representation of the marshaled key.
func (w *WebmeshPublicKey) Encode() (string, error) {
	raw, err := w.Marshal()
	if err != nil {
		return "", err
	}
	return p2pcrypto.ConfigEncodeKey(raw), nil
}

// Marshal returns the protobuf marshaled key.
func (w *WebmeshPublicKey) Marshal() ([]byte, error) {
	raw, _ := w.Raw()
	pb := cryptopb.PublicKey{
		Type: util.Pointer(WebmeshKeyType),
		Data: raw,
	}
	marshaled, err := proto.Marshal(&pb)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	return marshaled, nil
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
