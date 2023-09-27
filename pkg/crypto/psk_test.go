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
	"bytes"
	"strings"
	"testing"
)

func TestPSK(t *testing.T) {
	t.Parallel()

	t.Run("InvalidPSKs", func(t *testing.T) {
		t.Parallel()
		tc := []string{
			"",
			" ",
			strings.Repeat("+", DefaultPSKLength),
			string(bytes.Repeat([]byte{'\x00'}, DefaultPSKLength)),
			"/2349S@#$%$^&*()_+",
			"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		}
		for _, psk := range tc {
			if IsValidDefaultPSK(psk) {
				t.Fatalf("expected %s to be an invalid PSK", psk)
			}
		}
	})

	t.Run("ValidPSKs", func(t *testing.T) {
		t.Parallel()
		tc := []PSK{
			MustGeneratePSK(),
			MustGeneratePSK(),
			MustGeneratePSK(),
		}
		for _, psk := range tc {
			if !IsValidDefaultPSK(psk.String()) {
				t.Fatalf("expected %s to be a valid PSK", psk)
			}
		}
	})

	t.Run("SignAndVerify", func(t *testing.T) {
		t.Parallel()

		psk := MustGeneratePSK()
		msg := []byte("hello world")

		// We should be able to sign and verify a message.
		sig, err := psk.Sign(msg)
		if err != nil {
			t.Fatal(err)
		}
		if err := psk.Verify(msg, sig); err != nil {
			t.Fatal("expected signature to be valid, got", err)
		}
		// Signatures should be time invariant.
		if err := psk.Verify(msg, sig); err != nil {
			t.Fatal("expected signature to be valid, got", err)
		}
		// Invalid signature should return ErrInvalidSignature.
		if err := psk.Verify(msg, []byte("invalid")); err != ErrInvalidSignature {
			t.Fatal("expected ErrInvalidSignature, got", err)
		}
	})

	t.Run("DeterministicSignAndVerify", func(t *testing.T) {
		t.Parallel()

		psk := MustGeneratePSK()
		msg := []byte("hello world")

		// We should be able to sign and verify a message.
		sig, err := psk.DeterministicSign(msg)
		if err != nil {
			t.Fatal(err)
		}
		if err := psk.DeterministicVerify(msg, sig); err != nil {
			t.Fatal("expected signature to be valid, got", err)
		}
		// Signatures should be time invariant.
		if err := psk.DeterministicVerify(msg, sig); err != nil {
			t.Fatal("expected signature to be valid, got", err)
		}
		// Invalid signature should return ErrInvalidSignature.
		if err := psk.DeterministicVerify(msg, []byte("invalid")); err != ErrInvalidSignature {
			t.Fatal("expected ErrInvalidSignature, got", err)
		}
	})
}
