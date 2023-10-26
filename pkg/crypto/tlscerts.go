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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"os"
	"runtime"
	"time"
)

// TLSKeyType is a type of TLS key.
type TLSKeyType string

// TLSCertificate is a type alias to x509.Certificate.
// It's provided for convenience.
type TLSCertificate = x509.Certificate

const (
	// TLSKeyRSA is an RSA key.
	TLSKeyRSA TLSKeyType = "rsa"
	// TLSKeyECDSA is an ECDSA key.
	TLSKeyECDSA TLSKeyType = "ecdsa"
	// TLSKeyWebmesh is a Webmesh key. These are ed25519 keys.
	TLSKeyWebmesh TLSKeyType = "webmesh"

	// DefaultTLSKeyType is the default key type.
	DefaultTLSKeyType TLSKeyType = TLSKeyECDSA

	// DefaultCAName is the default name of the CA.
	DefaultCAName = "webmesh-ca"
	// DefaultCertName is the default name of the certificate.
	DefaultCertName = "webmesh-cert"
)

var (
	// ErrInvalidKeyType is returned when an invalid key type is used.
	ErrInvalidKeyType = fmt.Errorf("invalid key type")
	// ErrInvalidKeySize is returned when an invalid key size is used.
	ErrInvalidKeySize = fmt.Errorf("invalid key size")
)

func (t TLSKeyType) String() string {
	return string(t)
}

func (t TLSKeyType) IsValid() bool {
	switch t {
	case TLSKeyRSA, TLSKeyECDSA, TLSKeyWebmesh:
		return true
	default:
		return false
	}
}

// EncodeTLSCertificateToFile is a helper function to write a PEM encoded certificate
// to a file.
func EncodeTLSCertificateToFile(path string, cert *x509.Certificate) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return EncodeTLSCertificate(f, cert)
}

// EncodeTLSCertificate is a helper function to encode a certificate to PEM.
func EncodeTLSCertificate(o io.Writer, cert *x509.Certificate) error {
	return pem.Encode(o, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// DecodeTLSCertificateFromFile is a helper function to read a PEM encoded certificate
// from a file.
func DecodeTLSCertificateFromFile(path string) (*x509.Certificate, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open certificate file: %w", err)
	}
	defer f.Close()
	return DecodeTLSCertificate(f)
}

// DecodeTLSCertificate is a helper function to decode a certificate from PEM.
func DecodeTLSCertificate(i io.Reader) (*x509.Certificate, error) {
	certBytes, err := io.ReadAll(i)
	if err != nil {
		return nil, err
	}
	block, extra := pem.Decode(certBytes)
	if len(bytes.TrimSpace(extra)) != 0 {
		return nil, fmt.Errorf("unexpected extra PEM data")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

// EncodeTLSPrivateKeyToFile is a helper function to write a PEM encoded private key
// to a file.
func EncodeTLSPrivateKeyToFile(path string, key crypto.PrivateKey) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	err = EncodeTLSPrivateKey(f, key)
	if err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		// Try to set reasonable permissions.
		err = f.Chmod(0600)
		if err != nil {
			return err
		}
	}
	return nil
}

// EncodeTLSPrivateKey is a helper function to encode the given key to PEM.
func EncodeTLSPrivateKey(o io.Writer, key crypto.PrivateKey) error {
	var keyType string
	var keyBytes []byte
	var err error
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		keyType = "EC PRIVATE KEY"
		keyBytes, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return fmt.Errorf("error marshaling ECDSA private key: %w", err)
		}
	case *rsa.PrivateKey:
		keyType = "RSA PRIVATE KEY"
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
	case *ed25519.PrivateKey:
		keyType = "PRIVATE KEY"
		keyBytes = (*key)[:]
	case *WebmeshPrivateKey:
		// This is the same as an ed25519 private key.
		keyType = "PRIVATE KEY"
		keyBytes = key.Bytes()
	default:
		return fmt.Errorf("%w: %T", ErrInvalidKeyType, key)
	}
	return pem.Encode(o, &pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	})
}

// DecodeTLSPrivateKeyFromFile is a helper function to read a PEM encoded private key
// from a file.
func DecodeTLSPrivateKeyFromFile(path string) (crypto.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open private key file: %w", err)
	}
	defer f.Close()
	return DecodeTLSPrivateKey(f)
}

// DecodeTLSPrivateKey is a helper function to decode a private key from PEM.
func DecodeTLSPrivateKey(i io.Reader) (crypto.PrivateKey, error) {
	keyBytes, err := io.ReadAll(i)
	if err != nil {
		return nil, err
	}
	block, extra := pem.Decode(keyBytes)
	if len(bytes.TrimSpace(extra)) != 0 {
		return nil, fmt.Errorf("unexpected extra PEM data")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		data := make([]byte, ed25519.PrivateKeySize)
		if len(block.Bytes) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid ed25519 private key size: %d", len(block.Bytes))
		}
		copy(data, block.Bytes)
		return ed25519.PrivateKey(data), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidKeyType, block.Type)
	}
}

// NewTLSKey creates a new TLS key with the given keytype and size.
// Size is ignored for Webmesh keys.
func NewTLSKey(keyType TLSKeyType, size int) (privkey crypto.PrivateKey, pubkey crypto.PublicKey, err error) {
	if !keyType.IsValid() {
		err = fmt.Errorf("%w: %s", ErrInvalidKeyType, keyType)
		return
	}
	switch keyType {
	case TLSKeyRSA:
		privkey, err = rsa.GenerateKey(rand.Reader, size)
		if err != nil {
			return
		}
		pubkey = privkey.(*rsa.PrivateKey).Public()
	case TLSKeyECDSA:
		privkey, err = GenerateECDSAKey(size)
		if err != nil {
			return
		}
		pubkey = privkey.(*ecdsa.PrivateKey).Public()
	case TLSKeyWebmesh:
		privkey, err = GenerateKey()
		if err != nil {
			return
		}
		pubkey = privkey.(*WebmeshPrivateKey).PublicKey()
	}
	return
}

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
	// Key is a pre-existing key to use.
	Key PrivateKey
}

// Default sets the default values for the configuration.
func (c *CACertConfig) Default() {
	if c.CommonName == "" {
		c.CommonName = DefaultCAName
	}
	if c.ValidFor == 0 {
		c.ValidFor = 365 * 24 * time.Hour
	}
	if c.KeyType == "" {
		c.KeyType = DefaultTLSKeyType
	}
	if c.KeySize == 0 {
		c.KeySize = 256
	}
}

// GenerateCA generates a self-signed CA certificate.
func GenerateCA(cfg CACertConfig) (privkey crypto.PrivateKey, cert *x509.Certificate, err error) {
	cfg.Default()
	var pubkey crypto.PublicKey
	if cfg.Key != nil {
		privkey = cfg.Key.AsNative()
		pubkey = cfg.Key.PublicKey().AsNative()
	} else {
		privkey, pubkey, err = NewTLSKey(cfg.KeyType, cfg.KeySize)
		if err != nil {
			return
		}
		if cfg.KeyType == TLSKeyWebmesh {
			// Coerce to native formats.
			privkey = privkey.(*WebmeshPrivateKey).AsNative()
			pubkey = pubkey.(*WebmeshPublicKey).AsNative()
		}
	}
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(r.Int63()),
		Subject: pkix.Name{
			CommonName: cfg.CommonName,
		},
		DNSNames:              []string{cfg.CommonName},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().Add(cfg.ValidFor),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pubkey, privkey)
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
	// Key is a pre-existing key to use.
	Key PrivateKey
	// CACert is the CA certificate to use.
	CACert *x509.Certificate
	// CAKey is the CA key to use.
	CAKey crypto.PrivateKey
}

// Default sets the default values for the configuration.
func (c *IssueConfig) Default() {
	if c.CommonName == "" {
		c.CommonName = DefaultCertName
	}
	if c.ValidFor == 0 {
		c.ValidFor = 365 * 24 * time.Hour
	}
	if c.KeyType == "" {
		c.KeyType = DefaultTLSKeyType
	}
	if c.KeySize == 0 {
		c.KeySize = 256
	}
}

// IssueCertificate issues a certificate against the given CA with the given configuration.
// Key usages are assumed to be for client and server authentication.
func IssueCertificate(cfg IssueConfig) (privkey crypto.PrivateKey, cert *x509.Certificate, err error) {
	cfg.Default()
	var pubkey crypto.PublicKey
	if cfg.Key != nil {
		privkey = cfg.Key.AsNative()
		pubkey = cfg.Key.PublicKey().AsNative()
	} else {
		privkey, pubkey, err = NewTLSKey(cfg.KeyType, cfg.KeySize)
		if err != nil {
			return
		}
		if cfg.KeyType == TLSKeyWebmesh {
			// Coerce to native formats.
			privkey = privkey.(*WebmeshPrivateKey).AsNative()
			pubkey = pubkey.(*WebmeshPublicKey).AsNative()
		}
	}
	// Generate the certificate.
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(r.Int63()),
		Subject: pkix.Name{
			CommonName: cfg.CommonName,
		},
		DNSNames:              []string{cfg.CommonName},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().Add(cfg.ValidFor),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, cfg.CACert, pubkey, cfg.CAKey)
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
		KeyType:    DefaultTLSKeyType,
		KeySize:    256,
	})
	if err != nil {
		return
	}
	return IssueCertificate(IssueConfig{
		CommonName: "webmesh-selfsigned-server",
		ValidFor:   365 * 24 * time.Hour,
		KeyType:    DefaultTLSKeyType,
		KeySize:    256,
		CACert:     caCert,
		CAKey:      caPriv,
	})
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
		return nil, fmt.Errorf("%w: %d", ErrInvalidKeySize, size)
	}
	return ecdsa.GenerateKey(curve, rand.Reader)
}
