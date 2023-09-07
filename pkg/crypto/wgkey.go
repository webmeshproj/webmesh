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

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/crypto/pb"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WireGuardKeyType is the protobuf key type for WireGuard keys.
const WireGuardKeyType = 99

// PrivateKey is a private key used for encryption and identity over libp2p
type PrivateKey interface {
	p2pcrypto.PrivKey

	// WireGuardKey returns the WireGuard key.
	WireGuardKey() wgtypes.Key

	// PublicKey returns the PublicKey as a PublicKey interface.
	PublicKey() PublicKey

	// String returns the base64 encoded string representation of the key.
	String() string
}

// PublicKey is a public key used for encryption and identity over libp2p
type PublicKey interface {
	p2pcrypto.PubKey

	// WireGuardKey returns the WireGuard key.
	WireGuardKey() wgtypes.Key

	// String returns the base64 encoded string representation of the key.
	String() string
}

func init() {
	p2pcrypto.PrivKeyUnmarshallers[WireGuardKeyType] = func(data []byte) (p2pcrypto.PrivKey, error) {
		return ParsePrivateKeyV2(data)
	}
	p2pcrypto.PubKeyUnmarshallers[WireGuardKeyType] = func(data []byte) (p2pcrypto.PubKey, error) {
		return ParsePublicKeyV2(data)
	}
	p2pcrypto.KeyTypes = append(p2pcrypto.KeyTypes, WireGuardKeyType)
}

// GenerateKey generates a new private key.
func GenerateKeyV2() (PrivateKey, error) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	return &privateKey{ecdsa: priv}, nil
}

// MustGenerateKey generates a new private key or panics.
func MustGenerateKeyV2() PrivateKey {
	priv, err := GenerateKeyV2()
	if err != nil {
		panic(err)
	}
	return priv
}

// ParsePrivateKey parses a private key from a byte slice.
func ParsePrivateKeyV2(data []byte) (PrivateKey, error) {
	if len(data) != secp256k1.PrivKeyBytesLen {
		return nil, fmt.Errorf("expected secp256k1 data size to be %d", secp256k1.PrivKeyBytesLen)
	}
	priv := secp256k1.PrivKeyFromBytes(data)
	return &privateKey{ecdsa: priv}, nil
}

// ParsePublicKey parses a public key from a byte slice.
func ParsePublicKeyV2(data []byte) (PublicKey, error) {
	if len(data) != secp256k1.PubKeyBytesLenCompressed+32 {
		return nil, fmt.Errorf("expected secp256k1 data size to be %d", secp256k1.PubKeyBytesLenCompressed+32)
	}
	pub, err := secp256k1.ParsePubKey(data[secp256k1.PubKeyBytesLenCompressed:])
	if err != nil {
		return nil, err
	}
	return &publicKey{
		ecdsa: pub,
		wgkey: wgtypes.Key(data[:secp256k1.PubKeyBytesLenCompressed]),
	}, nil
}

type privateKey struct {
	ecdsa *secp256k1.PrivateKey
}

// Equals checks whether two PubKeys are the same
func (w *privateKey) Equals(in p2pcrypto.Key) bool {
	if _, ok := in.(*privateKey); !ok {
		return false
	}
	this := w.ecdsa.Serialize()
	out := in.(*privateKey).ecdsa.Serialize()
	return bytes.Equal(this[:], out[:])
}

// Raw returns the raw bytes of the key (not wrapped in the libp2p-crypto protobuf).
func (w *privateKey) Raw() ([]byte, error) {
	return w.ecdsa.Serialize(), nil
}

// Type returns the protobuf key type.
func (w *privateKey) Type() pb.KeyType {
	return WireGuardKeyType
}

// Cryptographically sign the given bytes
func (w *privateKey) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	sig := ecdsa.Sign(w.ecdsa, hash[:])
	return sig.Serialize(), nil
}

// Return a public key paired with this private key
func (w *privateKey) GetPublic() p2pcrypto.PubKey {
	return &publicKey{
		ecdsa: w.ecdsa.PubKey(),
		wgkey: wgtypes.Key(w.ecdsa.Serialize()).PublicKey(),
	}
}

// PublicKey returns the PublicKey as a PublicKey interface.
func (w *privateKey) PublicKey() PublicKey {
	return w.GetPublic().(*publicKey)
}

// WireGuardKey returns the WireGuard key.
func (w *privateKey) WireGuardKey() wgtypes.Key {
	return wgtypes.Key(w.ecdsa.Serialize())
}

// String returns the base64 encoded string representation of the key.
func (w *privateKey) String() string {
	return p2pcrypto.ConfigEncodeKey(w.ecdsa.Serialize())
}

type publicKey struct {
	ecdsa *secp256k1.PublicKey
	wgkey wgtypes.Key
}

// WireGuardKey returns the WireGuard key.
func (w *publicKey) WireGuardKey() wgtypes.Key {
	return w.wgkey
}

// Verify compares a signature against the input data
func (w *publicKey) Verify(data []byte, sigStr []byte) (success bool, err error) {
	sig, err := ecdsa.ParseDERSignature(sigStr)
	if err != nil {
		return false, err
	}
	hash := sha256.Sum256(data)
	return sig.Verify(hash[:], w.ecdsa), nil
}

// Type returns the protobuf key type.
func (w *publicKey) Type() pb.KeyType {
	return WireGuardKeyType
}

// Raw returns the raw bytes of the key (not wrapped in the libp2p-crypto protobuf).
func (w *publicKey) Raw() ([]byte, error) {
	// We append the X25519 public key to the end of the secp256k1 public key
	return append(w.wgkey[:], w.ecdsa.SerializeCompressed()...), nil
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

// String returns the base64 encoded string representation of the key.
func (w *publicKey) String() string {
	raw, _ := w.Raw()
	return p2pcrypto.ConfigEncodeKey(raw)
}
