package main

import (
	"fmt"

	"github.com/webmeshproj/webmesh/pkg/crypto"
)

func main() {
	key := crypto.MustGenerateKeyV2()
	fmt.Println(key)
	fmt.Println(key.PublicKey())
	fmt.Println(key.WireGuardKey().String())
	fmt.Println(key.WireGuardKey().PublicKey().String())

	encoded := key.String()
	decoded, _ := crypto.DecodePrivateKeyV2(encoded)
	if !decoded.Equals(key) {
		panic("decoded key not equal to original key")
	}

	encoded = key.PublicKey().String()
	decodedPub, err := crypto.DecodePublicKeyV2(encoded)
	if err != nil {
		panic(err)
	}
	if !decodedPub.Equals(key.PublicKey()) {
		panic("decoded public key not equal to original public key")
	}

	fmt.Println(decoded.WireGuardKey().String())
	fmt.Println(decodedPub.WireGuardKey().String())
}
