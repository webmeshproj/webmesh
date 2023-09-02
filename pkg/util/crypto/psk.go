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
	"hash"
)

func init() {
	// assert we have a crypto/rand source
	b := make([]byte, 1)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand is unavailable")
	}
}

// DefaultPSKLength is the default length of a PSK.
const DefaultPSKLength = 32

// ErrInvalidSignature is returned when a signature is invalid.
var ErrInvalidSignature = fmt.Errorf("invalid signature")

// ValidPSKChars is the set of valid characters for a PSK.
var ValidPSKChars = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// PSK is a pre-shared key.
type PSK []byte

// GeneratePSK generates a PSK.
func GeneratePSK() (PSK, error) {
	return GeneratePSKWithLength(DefaultPSKLength)
}

// GeneratePSKWithLength generates a PSK with a given length.
func GeneratePSKWithLength(length int) (PSK, error) {
	b := make(PSK, length)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	for i := range b {
		b[i] = ValidPSKChars[int(b[i])%len(ValidPSKChars)]
	}
	return b, nil
}

// MustGeneratePSK generates a PSK and panics on error.
func MustGeneratePSK() PSK {
	psk, err := GeneratePSK()
	if err != nil {
		panic(err)
	}
	return psk
}

func (p PSK) String() string {
	return string(p)
}

func (p PSK) SignatureSize() int {
	return sha256.New().Size()
}

// Sign creates a signature of the given data using this PSK.
func (p PSK) Sign(data []byte) ([]byte, error) {
	return Sign(data, p)
}

// Verify verifies the given signature against the given data using this PSK.
func (p PSK) Verify(data, signature []byte) error {
	return Verify(data, signature, p)
}

// Sign signs the given data using the given PSK.
func Sign(data []byte, psk PSK) ([]byte, error) {
	return SignWithHash(data, psk, sha256.New)
}

// Verify verifies the given signature against the given data using the given PSK.
func Verify(data, signature []byte, psk PSK) error {
	return VerifyWithHash(data, signature, psk, sha256.New)
}

// VerifyWithHash verifies the given signature against the given data using the given PSK and hash function.
func VerifyWithHash(data, signature []byte, psk PSK, hash func() hash.Hash) error {
	sig, err := SignWithHash(data, psk, hash)
	if err != nil {
		return err
	}
	if !bytes.Equal(sig, signature) {
		return ErrInvalidSignature
	}
	return nil
}

// SignWithHash signs the given data using the given PSK and hash function.
func SignWithHash(data []byte, psk PSK, hash func() hash.Hash) ([]byte, error) {
	h := hash()
	if _, err := h.Write(psk); err != nil {
		return nil, err
	}
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
