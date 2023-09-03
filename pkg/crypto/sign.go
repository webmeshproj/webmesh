package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

// Sign signs the given data using the given PSK.
func Sign(data []byte, psk PSK) ([]byte, error) {
	return signWithHash(data, psk, sha256.New)
}

// Verify verifies the given signature against the given data using the given PSK.
func Verify(data, signature []byte, psk PSK) error {
	return verifyWithHash(data, signature, psk, sha256.New)
}

// verifyWithHash verifies the given signature against the given data using the given PSK and hash function.
func verifyWithHash(data, signature []byte, psk PSK, hash func() hash.Hash) error {
	sig, err := signWithHash(data, psk, hash)
	if err != nil {
		return err
	}
	if !hmac.Equal(sig, signature) {
		return ErrInvalidSignature
	}
	return nil
}

// signWithHash signs the given data using the given PSK and hash function.
func signWithHash(data []byte, psk PSK, hash func() hash.Hash) ([]byte, error) {
	mac := hmac.New(hash, psk)
	if _, err := mac.Write(psk); err != nil {
		return nil, err
	}
	if _, err := mac.Write(data); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

func signDeterministicWithHash(data []byte, psk PSK, hash func() hash.Hash) ([]byte, error) {
	h := hash()
	if _, err := h.Write(psk); err != nil {
		return nil, err
	}
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func verifyDeterministicWithHash(data, signature []byte, psk PSK, hash func() hash.Hash) error {
	sig, err := signDeterministicWithHash(data, psk, hash)
	if err != nil {
		return err
	}
	if !bytes.Equal(sig, signature) {
		return ErrInvalidSignature
	}
	return nil
}
