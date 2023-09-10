package crypto

import (
	"bytes"
	"testing"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func TestWireGuardKeys(t *testing.T) {
	privkey := MustGenerateKey()
	pubkey := privkey.PublicKey()

	wgprivkey := privkey.WireGuardKey()
	wgpubkey := pubkey.WireGuardKey()

	// Ensure the wireguard keys are valid.
	if wgprivkey == [32]byte{} {
		t.Fatal("private key wireguard key is empty")
	}
	if wgpubkey == [32]byte{} {
		t.Fatal("public key wireguard key is empty")
	}
	if wgprivkey.PublicKey() != wgpubkey {
		t.Fatal("private key wireguard key does not match public key wireguard key")
	}

	if privkey.Type() != WireGuardKeyType {
		t.Fatal("private key type is not WireGuardKeyType")
	}
	if pubkey.Type() != WireGuardKeyType {
		t.Fatal("public key type is not WireGuardKeyType")
	}
}

func TestNativeIdentity(t *testing.T) {
	privkey := MustGenerateKey()
	pubkey := privkey.PublicKey()
	native, err := privkey.(*WireGuardKey).ToNativeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	// Ensure the native identity is valid and that the raw bytes
	// match the original private key.
	if native == nil {
		t.Fatal("native identity is nil")
	}
	if _, ok := native.(*p2pcrypto.Ed25519PrivateKey); !ok {
		t.Fatal("native identity is not an ed25519 private key")
	}
	raw, err := native.Raw()
	if err != nil {
		t.Fatal(err)
	}
	privRaw, _ := privkey.Raw()
	if !bytes.Equal(raw, privRaw) {
		t.Fatal("native identity raw bytes do not match original private key raw bytes")
	}

	// Same test for the public key
	nativepub, err := pubkey.(*WireGuardPublicKey).ToNativeIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if nativepub == nil {
		t.Fatal("native identity is nil")
	}
	if _, ok := nativepub.(*p2pcrypto.Ed25519PublicKey); !ok {
		t.Fatal("native identity is not an ed25519 public key")
	}
}

func TestEncodeWireGuardKeys(t *testing.T) {
	privkey := MustGenerateKey()
	pubkey := privkey.PublicKey()

	wgprivkey := privkey.WireGuardKey()
	wgpubkey := pubkey.WireGuardKey()

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

func TestNativeUnmarshalers(t *testing.T) {
	// The native unmarshalers should be able to decode the same keys that the
	// wireguard unmarshalers can decode.
	privkey := MustGenerateKey()
	pubkey := privkey.PublicKey()

	rawPriv, err := privkey.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	rawPub, err := pubkey.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	decodedPriv, err := p2pcrypto.UnmarshalPrivateKey([]byte(rawPriv))
	if err != nil {
		t.Fatal(err)
	}
	decodedPub, err := p2pcrypto.UnmarshalPublicKey([]byte(rawPub))
	if err != nil {
		t.Fatal(err)
	}

	if !decodedPriv.Equals(privkey) {
		t.Fatal("decoded private key not equal to original private key")
	}
	if !decodedPub.Equals(pubkey) {
		t.Fatal("decoded public key not equal to original public key")
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
	extracted, err := id.ExtractPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !extracted.Equals(key.PublicKey()) {
		t.Fatal("extracted public key does not match original public key")
	}
	if !extracted.(*WireGuardPublicKey).IsTruncated() {
		t.Fatal("extracted public key is not truncated")
	}
	matches := extracted.Equals(key.PublicKey())
	if !matches {
		t.Fatal("IDMatchesPublicKey returned false")
	}
	id, err = peer.IDFromPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("key ID is empty")
	}
	if id != key.ID() {
		t.Fatal("key ID does not match private key ID")
	}
}
