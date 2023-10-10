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
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// VerifyChainOnly is a function that can be used in a TLS configuration
// to only verify that the certificate chain is valid.
func VerifyChainOnly(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	roots := x509.NewCertPool()
	var cert *x509.Certificate
	for _, rawCert := range rawCerts {
		var err error
		cert, err = x509.ParseCertificate(rawCert)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}
		roots.AddCert(cert)
	}
	_, err := cert.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	return err
}

// VerifyConnectionChainOnly is a function that can be used in a TLS configuration
// to only verify that the certificate chain is valid.
func VerifyConnectionChainOnly(cs tls.ConnectionState) error {
	opts := x509.VerifyOptions{
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	_, err := cs.PeerCertificates[0].Verify(opts)
	return err
}
