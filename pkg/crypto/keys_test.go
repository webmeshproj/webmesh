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

import "testing"

func TestKeyMarshaling(t *testing.T) {
	key := MustGenerateKey()
	marshaled := key.String()

	wgpriv := key.PrivateKey()
	wgpub := key.PublicKey()

	parsed, err := ParseKey(marshaled)
	if err != nil {
		t.Fatal(err)
	}
	if !key.HostKey().Equals(parsed.HostKey()) {
		t.Fatal("host keys do not match")
	}
	if wgpriv.String() != parsed.PrivateKey().String() {
		t.Fatal("private WireGuard keys do not match")
	}
	if wgpub.String() != parsed.PublicKey().String() {
		t.Fatal("public WireGuard keys do not match")
	}
	if key.PublicHostString() != parsed.PublicHostString() {
		t.Fatal("public host keys do not match")
	}
	pubkey, err := ParseHostPublicKey(key.PublicHostString())
	if err != nil {
		t.Fatal(err)
	}
	if !pubkey.Equals(parsed.HostKey().GetPublic()) {
		t.Fatal("parsed public host key does not match")
	}
}
