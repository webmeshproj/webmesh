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
	"crypto/rand"
	"crypto/sha256"
	"fmt"
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

// IsValidDefaultPSK returns true if the given string is a valid PSK.
func IsValidDefaultPSK(s string) bool {
	return IsValidPSK(s, DefaultPSKLength)
}

// IsValidPSK returns true if the given string is a valid PSK.
func IsValidPSK(s string, length int) bool {
	return IsValidPSKBytes([]byte(s), length)
}

// IsValidPSKBytes returns true if the given byte slice is a valid PSK.
func IsValidPSKBytes(b []byte, length int) bool {
	if len(b) != length {
		return false
	}
	for _, c := range b {
		if !bytes.Contains(ValidPSKChars, []byte{c}) {
			return false
		}
	}
	return true
}

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

func (p PSK) IsValid() bool {
	return IsValidPSKBytes(p, len(p))
}

func (p PSK) SignatureSize() int {
	return hmac.New(sha256.New, p).Size()
}

func (p PSK) DeterministicSignatureSize() int {
	return sha256.New().Size()
}

// Sign creates a signature of the given data using this PSK.
func (p PSK) Sign(data []byte) ([]byte, error) {
	return Sign(data, p)
}

// DeterministicSign creates a signature of the given data using this PSK.
func (p PSK) DeterministicSign(data []byte) ([]byte, error) {
	return signDeterministicWithHash(data, p, sha256.New)
}

// Verify verifies the given signature against the given data using this PSK.
func (p PSK) Verify(data, signature []byte) error {
	return Verify(data, signature, p)
}

// DeterministicVerify verifies the given signature against the given data using this PSK.
func (p PSK) DeterministicVerify(data, signature []byte) error {
	return verifyDeterministicWithHash(data, signature, p, sha256.New)
}
