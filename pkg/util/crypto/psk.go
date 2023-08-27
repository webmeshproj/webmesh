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

import "crypto/rand"

func init() {
	// assert we have a crypto/rand source
	b := make([]byte, 1)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand is unavailable")
	}
}

// DefaultPSKLength is the default length of a PSK.
const DefaultPSKLength = 32

// ValidPSKChars is the set of valid characters for a PSK.
var ValidPSKChars = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// PSK is a pre-shared key.
type PSK []byte

func (p PSK) String() string {
	return string(p)
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
