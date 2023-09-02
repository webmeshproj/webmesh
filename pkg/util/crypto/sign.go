package crypto

import (
	"bytes"
	"crypto/sha256"
	"hash"
)

// Signer is a type that can sign data.
type Signer interface {
	// Sign signs the given data.
	Sign(data []byte) ([]byte, error)
	// Verify verifies the given signature against the given data.
	Verify(data, signature []byte) error
	// SignatureSize returns the size of the signature.
	SignatureSize() int
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
