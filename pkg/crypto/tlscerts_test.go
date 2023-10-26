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
	"crypto/ecdsa"
	"crypto/rsa"
	"os"
	"testing"
)

func TestNewTLSKeys(t *testing.T) {
	t.Parallel()
	tc := []struct {
		name    string
		typ     TLSKeyType
		size    int
		wantErr bool
	}{
		{
			name:    "InvalidType",
			typ:     TLSKeyType("invalid"),
			size:    0,
			wantErr: true,
		},
		{
			name:    "ValidRSAKey",
			typ:     TLSKeyRSA,
			size:    2048,
			wantErr: false,
		},
		{
			name:    "InvalidRSASize",
			typ:     TLSKeyRSA,
			size:    1,
			wantErr: true,
		},
		{
			name:    "Valid256ECDSAKey",
			typ:     TLSKeyECDSA,
			size:    256,
			wantErr: false,
		},
		{
			name:    "Valid384ECDSAKey",
			typ:     TLSKeyECDSA,
			size:    384,
			wantErr: false,
		},
		{
			name:    "Valid521ECDSAKey",
			typ:     TLSKeyECDSA,
			size:    521,
			wantErr: false,
		},
		{
			name:    "InvalidECDSASize",
			typ:     TLSKeyECDSA,
			size:    1,
			wantErr: true,
		},
		{
			name:    "ValidWebmeshKey",
			typ:     TLSKeyWebmesh,
			wantErr: false,
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := NewTLSKey(tt.typ, tt.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewTLSKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestTLSCertificateEncoder(t *testing.T) {
	t.Parallel()
	_, cert, err := GenerateSelfSignedServerCert()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp("", "cert")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	err = EncodeTLSCertificateToFile(f.Name(), cert)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeTLSCertificateFromFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.Raw, cert.Raw) {
		t.Fatal("decoded certificate does not match original")
	}
}

func TestTLSKeyEncoder(t *testing.T) {
	t.Parallel()

	t.Run("Defaults", func(t *testing.T) {
		key, _, err := GenerateSelfSignedServerCert()
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.CreateTemp("", "key")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())
		err = EncodeTLSPrivateKeyToFile(f.Name(), key)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeTLSPrivateKeyFromFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		dkey, ok := decoded.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatal("decoded key is not an ecdsa.PrivateKey")
		}
		if !dkey.Equal(key) {
			t.Fatal("decoded key does not match original")
		}
	})

	t.Run("RSA", func(t *testing.T) {
		key, _, err := NewTLSKey(TLSKeyRSA, 2048)
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.CreateTemp("", "key")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())
		err = EncodeTLSPrivateKeyToFile(f.Name(), key)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeTLSPrivateKeyFromFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		dkey, ok := decoded.(*rsa.PrivateKey)
		if !ok {
			t.Fatal("decoded key is not an rsa.PrivateKey")
		}
		if !dkey.Equal(key) {
			t.Fatal("decoded key does not match original")
		}
	})

	t.Run("ECDSA", func(t *testing.T) {
		key, _, err := NewTLSKey(TLSKeyECDSA, 256)
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.CreateTemp("", "key")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())
		err = EncodeTLSPrivateKeyToFile(f.Name(), key)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeTLSPrivateKeyFromFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		dkey, ok := decoded.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatal("decoded key is not an ecdsa.PrivateKey")
		}
		if !dkey.Equal(key) {
			t.Fatal("decoded key does not match original")
		}
	})

	t.Run("ED25519", func(t *testing.T) {
		key, _, err := NewTLSKey(TLSKeyWebmesh, 0)
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.CreateTemp("", "key")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())
		err = EncodeTLSPrivateKeyToFile(f.Name(), key)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeTLSPrivateKeyFromFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		dkey, ok := decoded.(*WebmeshPrivateKey)
		if !ok {
			t.Fatal("decoded key is not an WebmeshPrivateKey")
		}
		if !dkey.Equals(key.(*WebmeshPrivateKey)) {
			t.Fatal("decoded key does not match original")
		}
	})
}
