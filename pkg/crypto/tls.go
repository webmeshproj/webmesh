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

// VerifyConnectionChainOnly is a function that can be used in a TLS configuration
// to only verify that the certificate chain is valid.
func VerifyConnectionChainOnly(cs tls.ConnectionState) error {
	opts := x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		Intermediates: x509.NewCertPool(),
	}
	var leaf *x509.Certificate
	for _, cert := range cs.PeerCertificates {
		c := cert
		if c.IsCA {
			opts.Roots.AddCert(c)
			continue
		}
		opts.Intermediates.AddCert(c)
		leaf = c
	}
	_, err := leaf.Verify(opts)
	if err != nil {
		return fmt.Errorf("failed to verify certificate: %w", err)
	}
	return err
}
