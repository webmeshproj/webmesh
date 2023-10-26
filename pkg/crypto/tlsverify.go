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
	"crypto/x509"
	"fmt"
)

// ErrInvalidPeerCertificate is returned when a TLS connection has invalid peer certificate.
var ErrInvalidPeerCertificate = fmt.Errorf("invalid peer certificate")

// VerifyPeerCertificateFunc is a function that can be used in a TLS configuration
// to verify the peer certificate.
type VerifyPeerCertificateFunc func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

// VerifyCertificateChainFromFile returns a function that can be used in a TLS configuration
// to verify that the certificate chain is valid according to the PEM-encoded data in the
// given file.
func VerifyCertificateChainFromFile(filename string) (VerifyPeerCertificateFunc, error) {
	cert, err := DecodeTLSCertificateFromFile(filename)
	if err != nil {
		return nil, err
	}
	return VerifyCertificateChainOnly([]*x509.Certificate{cert}), nil
}

// VerifyCertificateChainOnly returns a function that can be used in a TLS configuration
// to only verify that the certificate chain is valid.
func VerifyCertificateChainOnly(rootcerts []*x509.Certificate) VerifyPeerCertificateFunc {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		var roots *x509.CertPool
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		opts := x509.VerifyOptions{
			Intermediates: x509.NewCertPool(),
			Roots:         roots,
		}
		for _, cert := range rootcerts {
			opts.Roots.AddCert(cert)
		}
		peercert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidPeerCertificate, err)
		}
		_, err = peercert.Verify(opts)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidPeerCertificate, err)
		}
		return nil
	}
}
