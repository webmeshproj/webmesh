package crypto

import (
	"bytes"
	"testing"
)

func TestEncodedWireGuardKeys(t *testing.T) {
	privkey := MustGenerateKey()
	pubkey := privkey.PublicKey()
	wgprivkey := privkey.WireGuardKey()
	wgpubkey := pubkey.WireGuardKey()

	if privkey.Type() != WireGuardKeyType {
		t.Fatal("private key type is not WireGuardKeyType")
	}
	if pubkey.Type() != WireGuardKeyType {
		t.Fatal("public key type is not WireGuardKeyType")
	}

	encodedPriv, err := privkey.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decodedPriv, err := DecodePrivateKey(encodedPriv)
	if err != nil {
		t.Fatal(err)
	}
	if !decodedPriv.Equals(privkey) {
		t.Fatal("decoded private key not equal to original private key")
	}
	if decodedPriv.Type() != WireGuardKeyType {
		t.Fatal("decoded private key type is not WireGuardKeyType")
	}
	decodedWg := decodedPriv.WireGuardKey()
	if !bytes.Equal(decodedWg[:], wgprivkey[:]) {
		t.Fatal("decoded private key wireguard key not equal to original private key wireguard key")
	}

	encodedPub, err := pubkey.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decodedPub, err := DecodePublicKey(encodedPub)
	if err != nil {
		t.Fatal(err)
	}
	if !decodedPub.Equals(pubkey) {
		t.Fatal("decoded public key not equal to original public key")
	}
	if decodedPub.Type() != WireGuardKeyType {
		t.Fatal("decoded public key type is not WireGuardKeyType")
	}
	decodedWg = decodedPub.WireGuardKey()
	if !bytes.Equal(decodedWg[:], wgpubkey[:]) {
		t.Fatal("decoded public key wireguard key not equal to original public key wireguard key")
	}
}

func TestWireGuardKeySignatures(t *testing.T) {
	key := MustGenerateKey()
	data := []byte("hello world")

	sig, err := key.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	pubkey := key.PublicKey()
	if ok, err := pubkey.Verify(data, sig); err != nil {
		t.Fatal("signature verification failed:", err)
	} else if !ok {
		t.Fatal("signature verification failed: signature was not valid")
	}
}

func TestWireGuardKeyIDs(t *testing.T) {
	key := MustGenerateKey()
	id := key.ID()
	if id == "" {
		t.Fatal("key ID is empty")
	}
	if id != key.PublicKey().ID() {
		t.Fatal("key ID does not match public key ID")
	}

	extracted, err := ExtractPublicKeyFromID(id)
	if err != nil {
		t.Fatal(err)
	}
	if !extracted.Equals(key.PublicKey()) {
		t.Fatal("extracted public key does not match original public key")
	}
}
