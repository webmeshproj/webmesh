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
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"os"
	"sort"
	"strings"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	cryptopb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/peer"
	b58 "github.com/mr-tron/base58/base58"
	oed25519 "github.com/oasisprotocol/curve25519-voi/primitives/ed25519"
	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/proto"

	"github.com/webmeshproj/webmesh/pkg/common"
)

// WebmeshKeyType is the protobuf key type for Webmesh keys.
const WebmeshKeyType cryptopb.KeyType = 5

// StdPrivateKey is a type alias to the std crypto private key.
// It's provided for convenience.
type StdPrivateKey = crypto.PrivateKey

func init() {
	// Make sure the random source is initialized.
	if _, err := rand.Read(make([]byte, 1)); err != nil {
		panic(err)
	}
	// Register key type with libp2p
	cryptopb.KeyType_name[int32(WebmeshKeyType)] = "Webmesh"
	cryptopb.KeyType_value["Webmesh"] = int32(WebmeshKeyType)
	p2pcrypto.KeyTypes = append(p2pcrypto.KeyTypes, int(WebmeshKeyType))
	p2pcrypto.PrivKeyUnmarshallers[WebmeshKeyType] = func(data []byte) (p2pcrypto.PrivKey, error) {
		key, err := ParsePrivateKey(data)
		if err != nil {
			return nil, err
		}
		return key.AsIdentity(), nil
	}
	p2pcrypto.PubKeyUnmarshallers[WebmeshKeyType] = func(data []byte) (p2pcrypto.PubKey, error) {
		key, err := ParsePublicKey(data)
		if err != nil {
			return nil, err
		}
		return key.AsIdentity(), nil
	}
}

// Key is the interface that all keys satisfy.
type Key interface {
	// ID returns the peer ID of the key as an encoded string.
	// This will always be the ID of the public key.
	ID() string

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

	// Equals returns true if the given key is equal to this key.
	Equals(Key) bool
}

// PrivateKey is a private key used for encryption and identity over webmesh.
type PrivateKey interface {
	Key

	// AsIdentity returns the private key as a libp2p crypto private key.
	// This changes the type of the key to a ed25519 private key.
	AsIdentity() p2pcrypto.PrivKey

	// AsNative returns the private key as a native crypto private key.
	AsNative() ed25519.PrivateKey

	// PublicKey returns the PublicKey as a PublicKey interface.
	PublicKey() PublicKey
}

// PublicKey is a public key used for encryption and identity over webmesh.
type PublicKey interface {
	Key

	// AsIdentity returns the public key as a libp2p crypto public key.
	// This changes the type of the key to a ed25519 public key.
	AsIdentity() p2pcrypto.PubKey

	// AsNative returns the public key as a native crypto public key.
	AsNative() ed25519.PublicKey
}

// SortedKeys is a slice of public keys that can be sorted.
type SortedKeys []PublicKey

func (s SortedKeys) Len() int           { return len(s) }
func (s SortedKeys) Less(i, j int) bool { return string(s[i].Bytes()) < string(s[j].Bytes()) }
func (s SortedKeys) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

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

// EncodeKeyToFile encodes a key to a file.
func EncodeKeyToFile(key Key, file string) error {
	encoded, err := key.Encode()
	if err != nil {
		return err
	}
	return os.WriteFile(file, []byte(encoded), 0600)
}

// DecodePrivateKeyFromFile decodes a private key from a file.
func DecodePrivateKeyFromFile(path string) (PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return DecodePrivateKey(strings.TrimSpace(string(data)))
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

// PubKeyFromID returns the public key from the given peer ID.
func PubKeyFromID(id string) (PublicKey, error) {
	idBytes, err := b58.Decode(id)
	if err != nil {
		return nil, fmt.Errorf("decode peer ID: %w", err)
	}
	key, err := peer.ID(idBytes).ExtractPublicKey()
	if err != nil {
		return nil, fmt.Errorf("extract public key from peer ID: %w", err)
	}
	raw, err := key.Raw()
	if err != nil {
		return nil, fmt.Errorf("get raw public key: %w", err)
	}
	return ParsePublicKey(raw)
}

// PrivateKeyFromNative returns a private key from a native crypto private key.
func PrivateKeyFromNative(inkey crypto.PrivateKey) (PrivateKey, error) {
	in, ok := inkey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid private key type: %T", in)
	}
	if len(in) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: %d", len(in))
	}
	var raw [ed25519.PrivateKeySize]byte
	copy(raw[:], in)
	return &WebmeshPrivateKey{
		raw: raw,
		typ: WebmeshKeyType,
	}, nil
}

// MustPrivateKeyFromNative returns a private key from a native crypto private key or panics.
func MustPrivateKeyFromNative(in crypto.PublicKey) PrivateKey {
	key, err := PrivateKeyFromNative(in)
	if err != nil {
		panic(err)
	}
	return key
}

// PublicKeyFromNative returns a public key from a native crypto public key.
func PublicKeyFromNative(inkey crypto.PublicKey) (PublicKey, error) {
	in, ok := inkey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid private key type: %T", in)
	}
	if len(in) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: %d", len(in))
	}
	var raw [ed25519.PublicKeySize]byte
	copy(raw[:], in)
	return &WebmeshPublicKey{
		raw: raw,
		typ: WebmeshKeyType,
	}, nil
}

// MustPublicKeyFromNative returns a public key from a native crypto public key or panics.
func MustPublicKeyFromNative(in crypto.PublicKey) PublicKey {
	key, err := PublicKeyFromNative(in)
	if err != nil {
		panic(err)
	}
	return key
}

// PrivateKeyFromIdentity returns a private key from a libp2p crypto private key.
func PrivateKeyFromIdentity(inkey p2pcrypto.PrivKey) (PrivateKey, error) {
	data, err := inkey.Raw()
	if err != nil {
		return nil, fmt.Errorf("get raw private key: %w", err)
	}
	return ParsePrivateKey(data)
}

// PublicKeyFromIdentity returns a public key from a libp2p crypto public key.
func PublicKeyFromIdentity(inkey p2pcrypto.PubKey) (PublicKey, error) {
	data, err := inkey.Raw()
	if err != nil {
		return nil, fmt.Errorf("get raw public key: %w", err)
	}
	return ParsePublicKey(data)
}

// WebmeshPrivateKey is a private key used for webmesh transport.
type WebmeshPrivateKey struct {
	raw [ed25519.PrivateKeySize]byte
	typ cryptopb.KeyType
}

// AsIdentity returns the private key as a libp2p crypto private key.
// This changes the type of the key to a ed25519 private key.
func (w *WebmeshPrivateKey) AsIdentity() p2pcrypto.PrivKey {
	// We marshal the key back and forth assuming it was
	// already validated.
	ed25519, _ := p2pcrypto.UnmarshalEd25519PrivateKey(w.Bytes())
	return ed25519
}

// AsNative returns the private key as a native crypto private key.
func (w *WebmeshPrivateKey) AsNative() ed25519.PrivateKey {
	out := make([]byte, ed25519.PrivateKeySize)
	copy(out, w.raw[:])
	return ed25519.PrivateKey(out)
}

// Type returns the protobuf key type.
func (w *WebmeshPrivateKey) Type() cryptopb.KeyType {
	return w.typ
}

// ID returns the peer ID of the key.
func (w *WebmeshPrivateKey) ID() string {
	return w.PublicKey().ID()
}

// Bytes returns the raw bytes of the key. This is the same as Key.Raw
// without needing to do an error check.
func (w *WebmeshPrivateKey) Bytes() []byte {
	out := make([]byte, 64)
	copy(out, w.raw[:])
	return out
}

// Equals returns true if the given key is equal to this key.
func (w *WebmeshPrivateKey) Equals(inKey Key) bool {
	in, ok := inKey.(*WebmeshPrivateKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(w.Bytes(), in.Bytes()) == 1
}

// Sign cryptographically signs the given bytes.
func (w *WebmeshPrivateKey) Sign(data []byte) ([]byte, error) {
	return ed25519.Sign(w.Bytes(), data), nil
}

// PublicKey returns the public key.
func (w *WebmeshPrivateKey) PublicKey() PublicKey {
	var out [ed25519.PublicKeySize]byte
	copy(out[:], w.raw[ed25519.PublicKeySize:])
	return &WebmeshPublicKey{raw: out, typ: WebmeshKeyType}
}

// WireGuardKey computes the private key's wireguard key.
func (w *WebmeshPrivateKey) WireGuardKey() wgtypes.Key {
	key := oed25519.PrivateKey(w.Bytes())
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
	pb := cryptopb.PrivateKey{
		Type: common.Pointer(WebmeshKeyType),
		Data: w.Bytes(),
	}
	marshaled, err := proto.Marshal(&pb)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	return marshaled, nil
}

// WebmeshPublicKey is a public key used for webmesh transport.
type WebmeshPublicKey struct {
	raw [ed25519.PublicKeySize]byte
	typ cryptopb.KeyType
}

// Type returns the protobuf key type.
func (w *WebmeshPublicKey) Type() cryptopb.KeyType {
	return w.typ
}

// ID returns the peer ID of the key.
func (w *WebmeshPublicKey) ID() string {
	id, _ := peer.IDFromPublicKey(w.AsIdentity())
	return id.String()
}

// AsIdentity returns the public key as a libp2p crypto public key.
// This changes the type of the key to a ed25519 public key.
func (w *WebmeshPublicKey) AsIdentity() p2pcrypto.PubKey {
	// We marshal the key back and forth assuming it was
	// already validated.
	ed25519, _ := p2pcrypto.UnmarshalEd25519PublicKey(w.Bytes())
	return ed25519
}

// AsNative returns the public key as a native crypto public key.
func (w *WebmeshPublicKey) AsNative() ed25519.PublicKey {
	return ed25519.PublicKey(w.Bytes())
}

// Bytes returns the raw bytes of the key. This is the same as Key.Raw
// without needing to do an error check.
func (w *WebmeshPublicKey) Bytes() []byte {
	out := make([]byte, ed25519.PublicKeySize)
	copy(out, w.raw[:])
	return out
}

// Equals returns true if the given key is equal to this key.
func (w *WebmeshPublicKey) Equals(in Key) bool {
	inKey, ok := in.(*WebmeshPublicKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(w.raw[:], inKey.raw[:]) == 1
}

// Verify compares a signature against the input data
func (w *WebmeshPublicKey) Verify(data []byte, sig []byte) (success bool, err error) {
	return ed25519.Verify(w.Bytes(), data, sig), nil
}

// WireGuardKey computes the private key's wireguard key.
func (w *WebmeshPublicKey) WireGuardKey() wgtypes.Key {
	key := oed25519.PublicKey(w.Bytes())
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
	pb := cryptopb.PublicKey{
		Type: common.Pointer(WebmeshKeyType),
		Data: w.Bytes(),
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
