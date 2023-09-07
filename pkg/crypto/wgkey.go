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
	"crypto/hmac"
	"crypto/sha256"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/crypto/pb"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const WireGuardKeyType = 99

func init() {
	crypto.PrivKeyUnmarshallers[WireGuardKeyType] = func(data []byte) (crypto.PrivKey, error) {
		var priv wgtypes.Key
		copy(priv[:], data)
		return &wgKey{priv}, nil
	}
	crypto.PubKeyUnmarshallers[WireGuardKeyType] = func(data []byte) (crypto.PubKey, error) {
		var pub wgtypes.Key
		copy(pub[:], data)
		return &wgKey{pub}, nil
	}
	crypto.KeyTypes = append(crypto.KeyTypes, WireGuardKeyType)
}

type wgKey struct {
	wgtypes.Key
}

// GenerateKey generates a new private key.
func GenerateKeyV2() (crypto.PrivKey, error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	return &wgKey{priv}, nil
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
func (w *wgKey) Equals(in crypto.Key) bool {
	if _, ok := in.(*wgKey); !ok {
		return false
	}
	return bytes.Equal(w.Key[:], in.(*wgKey).Key[:])
}

// Raw returns the raw bytes of the key (not wrapped in the libp2p-crypto protobuf).
func (w *wgKey) Raw() ([]byte, error) {
	return w.Key[:], nil
}

// Type returns the protobuf key type.
func (w *wgKey) Type() pb.KeyType {
	return WireGuardKeyType
}

// Cryptographically sign the given bytes
func (w *wgKey) Sign(data []byte) ([]byte, error) {
	pubKey := w.Key.PublicKey()
	h := hmac.New(sha256.New, pubKey[:])
	h.Write(data)
	return h.Sum(nil), nil
}

// Return a public key paired with this private key
func (w *wgKey) GetPublic() crypto.PubKey {
	return &wgKey{w.Key.PublicKey()}
}

// Verify that the given signature is valid
func (w *wgKey) Verify(data []byte, sig []byte) (bool, error) {
	h := hmac.New(sha256.New, w.Key[:])
	h.Write(data)
	vsig := h.Sum(nil)
	return hmac.Equal(vsig, sig), nil
}
