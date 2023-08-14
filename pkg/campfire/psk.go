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

package campfire

import "crypto/rand"

var validPSKChars = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// GeneratePSK generates a random PSK of length PSKSize.
func GeneratePSK() ([]byte, error) {
	out := make([]byte, PSKSize)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	for i, b := range out {
		out[i] = validPSKChars[b%byte(len(validPSKChars))]
	}
	return out, nil
}

// MustGeneratePSK generates a random PSK of length PSKSize.
// It panics if an error occurs.
func MustGeneratePSK() []byte {
	psk, err := GeneratePSK()
	if err != nil {
		panic(err)
	}
	return psk
}
