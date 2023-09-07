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
	"fmt"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/crypto/pb"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const WireGuardKeyType = 99

func init() {
	crypto.PrivKeyUnmarshallers[WireGuardKeyType] = func(data []byte) (crypto.PrivKey, error) {
		var priv wgtypes.Key
		copy(priv[:], data)
		return &wgPrivateKey{priv}, nil
	}
	crypto.PubKeyUnmarshallers[WireGuardKeyType] = func(data []byte) (crypto.PubKey, error) {
		var pub wgtypes.Key
		copy(pub[:], data)
		return &wgPublicKey{pub}, nil
	}
	crypto.KeyTypes = append(crypto.KeyTypes, WireGuardKeyType)
}

type wgPrivateKey struct {
	wgtypes.Key
}

// GenerateKey generates a new private key.
func GenerateKeyV2() (crypto.PrivKey, error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	return &wgPrivateKey{priv}, nil
}

// MustGenerateKey generates a new private key or panics.
func MustGenerateKeyV2() crypto.PrivKey {
	priv, err := GenerateKeyV2()
	if err != nil {
		panic(err)
	}
	return priv
}

// Equals checks whether two PubKeys are the same
func (w *wgPrivateKey) Equals(in crypto.Key) bool {
	if _, ok := in.(*wgPrivateKey); !ok {
		return false
	}
	this := w.PublicKey()
	out := in.(*wgPrivateKey).PublicKey()
	return bytes.Equal(this[:], out[:])
}

// Raw returns the raw bytes of the key (not wrapped in the libp2p-crypto protobuf).
func (w *wgPrivateKey) Raw() ([]byte, error) {
	return w.Key[:], nil
}

// Type returns the protobuf key type.
func (w *wgPrivateKey) Type() pb.KeyType {
	return WireGuardKeyType
}

// Cryptographically sign the given bytes
func (w *wgPrivateKey) Sign(data []byte) ([]byte, error) {
	key, err := crypto.UnmarshalSecp256k1PrivateKey(w.Key[:])
	if err != nil {
		return nil, fmt.Errorf("unmarshal private key: %w", err)
	}
	rawpub, err := key.GetPublic().Raw()
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}
	sig, err := key.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("sign data: %w", err)
	}
	return append(rawpub, sig...), nil
}

// Return a public key paired with this private key
func (w *wgPrivateKey) GetPublic() crypto.PubKey {
	return &wgPublicKey{w.PublicKey()}
}

type wgPublicKey struct {
	wgtypes.Key
}

// Equals checks whether two PubKeys are the same
func (w *wgPublicKey) Equals(in crypto.Key) bool {
	key, ok := in.(*wgPublicKey)
	if !ok {
		return false
	}
	return bytes.Equal(w.Key[:], key.Key[:])
}

// Raw returns the raw bytes of the key (not wrapped in the libp2p-crypto protobuf).
func (w *wgPublicKey) Raw() ([]byte, error) {
	return w.Key[:], nil
}

// Type returns the protobuf key type.
func (w *wgPublicKey) Type() pb.KeyType {
	return WireGuardKeyType
}

const PubKeySize = 32

// Verify compares a signature against the input data
func (w *wgPublicKey) Verify(data []byte, sigStr []byte) (success bool, err error) {
	// Pull the full public key off the top of the signature
	if len(sigStr) < PubKeySize+1 {
		return false, fmt.Errorf("signature too short")
	}
	pub := sigStr[:PubKeySize+1]
	sigStr = sigStr[PubKeySize+1:]
	// sig, err := ecdsa.ParseDERSignature(sigStr)
	key, err := crypto.UnmarshalSecp256k1PublicKey(pub)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal public key: %w", err)
	}
	return key.Verify(data, sigStr)
}
