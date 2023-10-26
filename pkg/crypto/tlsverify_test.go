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
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestVerifyConnectionChainOnly(t *testing.T) {
	t.Parallel()

	cakey, cacert, err := GenerateCA(CACertConfig{})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cacert)
	key, cert, err := IssueCertificate(IssueConfig{
		CAKey:  cakey,
		CACert: cacert,
	})
	if err != nil {
		t.Fatal(err)
	}
	var encodedCert, encodedKey bytes.Buffer
	err = EncodeTLSCertificate(&encodedCert, cert)
	if err != nil {
		t.Fatal(err)
	}
	err = EncodeTLSPrivateKey(&encodedKey, key)
	if err != nil {
		t.Fatal(err)
	}
	servercert, err := tls.X509KeyPair(encodedCert.Bytes(), encodedKey.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	certs := []tls.Certificate{servercert}
	tlsConfig := &tls.Config{Certificates: certs}
	ln, err := tls.Listen("tcp", "localhost:0", tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			_ = c.(*tls.Conn).Handshake()
		}
	}()

	t.Run("NoVerifiedChains", func(t *testing.T) {
		_, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			InsecureSkipVerify:    true,
			VerifyPeerCertificate: VerifyCertificateChainOnly(nil),
		})
		if err == nil {
			t.Fatal("expected local error")
		}
	})

	t.Run("VerifiedChains", func(t *testing.T) {
		_, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			InsecureSkipVerify:    true,
			VerifyPeerCertificate: VerifyCertificateChainOnly([]*x509.Certificate{cacert}),
		})
		if err != nil {
			t.Fatal("unexpected local error:", err)
		}
	})

	t.Run("InvalidChain", func(t *testing.T) {
		_, cert, err := GenerateSelfSignedServerCert()
		if err != nil {
			t.Fatal(err)
		}
		_, err = tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			InsecureSkipVerify:    true,
			VerifyPeerCertificate: VerifyCertificateChainOnly([]*x509.Certificate{cert}),
		})
		if err == nil {
			t.Fatal("expected local error")
		}
	})
}
