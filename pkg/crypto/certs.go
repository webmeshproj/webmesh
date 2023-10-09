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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	mrand "math/rand"
	"time"
)

// TLSKeyType is a type of TLS key.
type TLSKeyType string

const (
	// TLSKeyRSA is an RSA key.
	TLSKeyRSA TLSKeyType = "rsa"
	// TLSKeyECDSA is an ECDSA key.
	TLSKeyECDSA TLSKeyType = "ecdsa"
)

// CACertConfig is a configuration for a self-signed CA certificate.
type CACertConfig struct {
	// CommonName is the common name of the certificate.
	CommonName string
	// ValidFor is the duration the certificate is valid for.
	ValidFor time.Duration
	// KeyType is the type of key to use.
	KeyType TLSKeyType
	// KeySize is the size of the key to use.
	KeySize int
}

// GenerateCA generates a self-signed CA certificate.
func GenerateCA(cfg CACertConfig) (privKey crypto.PrivateKey, cert *x509.Certificate, err error) {
	var pubKey crypto.PublicKey
	switch cfg.KeyType {
	case TLSKeyRSA:
		privKey, err = rsa.GenerateKey(rand.Reader, cfg.KeySize)
		if err != nil {
			return
		}
		pubKey = privKey.(*rsa.PrivateKey).Public()
	case TLSKeyECDSA:
		privKey, err = GenerateECDSAKey(cfg.KeySize)
		if err != nil {
			return
		}
		pubKey = privKey.(*ecdsa.PrivateKey).Public()
	default:
		err = fmt.Errorf("unsupported key type: %s", cfg.KeyType)
		return
	}
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(r.Int63()),
		Subject: pkix.Name{
			CommonName: cfg.CommonName,
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().Add(cfg.ValidFor),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pubKey, privKey)
	if err != nil {
		return
	}
	cert, err = x509.ParseCertificate(caBytes)
	return
}

// IssueConfig is a configuration for issuing a certificate.
type IssueConfig struct {
	// CommonName is the common name of the certificate.
	CommonName string
	// ValidFor is the duration the certificate is valid for.
	ValidFor time.Duration
	// KeyType is the type of key to use.
	KeyType TLSKeyType
	// KeySize is the size of the key to use.
	KeySize int
}

// IssueCertificate issues a certificate against the given CA with the given configuration.
func IssueCertificate(cfg IssueConfig, caCert *x509.Certificate, caKey crypto.PrivateKey) (privKey crypto.PrivateKey, cert *x509.Certificate, err error) {
	var pubKey crypto.PublicKey
	switch cfg.KeyType {
	case TLSKeyRSA:
		privKey, err = rsa.GenerateKey(rand.Reader, cfg.KeySize)
		if err != nil {
			return
		}
		pubKey = privKey.(*rsa.PrivateKey).Public()
	case TLSKeyECDSA:
		privKey, err = GenerateECDSAKey(cfg.KeySize)
		if err != nil {
			return
		}
		pubKey = privKey.(*ecdsa.PrivateKey).Public()
	default:
		err = fmt.Errorf("unsupported key type: %s", cfg.KeyType)
		return
	}
	// Generate the certificate.
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(r.Int63()),
		Subject: pkix.Name{
			CommonName: cfg.CommonName,
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().Add(cfg.ValidFor),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pubKey, caKey)
	if err != nil {
		return
	}
	cert, err = x509.ParseCertificate(certBytes)
	return
}

// GenerateSelfSignedServerCert generates a self-signed server certificate
// with the built-in defaults.
func GenerateSelfSignedServerCert() (privKey crypto.PrivateKey, cert *x509.Certificate, err error) {
	caPriv, caCert, err := GenerateCA(CACertConfig{
		CommonName: "webmesh-selfsigned-ca",
		ValidFor:   365 * 24 * time.Hour,
		KeyType:    TLSKeyECDSA,
		KeySize:    256,
	})
	if err != nil {
		return
	}
	return IssueCertificate(IssueConfig{
		CommonName: "webmesh-selfsigned-server",
		ValidFor:   365 * 24 * time.Hour,
		KeyType:    TLSKeyECDSA,
		KeySize:    256,
	}, caCert, caPriv)
}

// GenerateECDSAKey generates an ECDSA key using an elliptic curve of the given size.
func GenerateECDSAKey(size int) (*ecdsa.PrivateKey, error) {
	var curve elliptic.Curve
	switch size {
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported key size: %d", size)
	}
	return ecdsa.GenerateKey(curve, rand.Reader)
}
