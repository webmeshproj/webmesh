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

// Package pki contains an interface for managing the PKI for a cluster using mTLS.
package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	mrand "math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/webmeshproj/node/pkg/ctlcmd/config"
)

const (
	// DefaultCAName is the default CA name.
	DefaultCAName = "webmesh-ca"
	// DefaultKeyType is the default key type.
	DefaultKeyType = "ecdsa"
	// DefaultKeySize is the default key size.
	DefaultKeySize = 256
	// DefaultAdminName is the default admin name.
	DefaultAdminName = "admin"
	// DefaultCAExpiry is the default CA expiry.
	DefaultCAExpiry = 365 * 24 * time.Hour // 1 year
	// DefaultNodeExpiry is the default node expiry.
	DefaultNodeExpiry = 90 * 24 * time.Hour // 90 days
	// CADirectory is the name of the relative directory containing the CA.
	CADirectory = "ca"
	// NodesDirectory is the name of the relative directory containing the nodes.
	NodesDirectory = "nodes"

	keyFileName  = "tls.key"
	certFileName = "tls.crt"
	caFileName   = "ca.crt"
)

// PKI is an interface for managing the PKI for a cluster using mTLS.
type PKI interface {
	// Generate generates a new PKI.
	Generate(*GenerateOptions) error
	// Issue issues a new certificate.
	Issue(*IssueOptions) error
	// GenerateConfig generates a new config.
	GenerateConfig(*GenerateConfigOptions) error
}

// GenerateOptions are options for generating a new PKI.
type GenerateOptions struct {
	// CAName is the name of the CA.
	CAName string
	// AdminName is the name of the admin user.
	AdminName string
	// KeySize is the size of the keys to generate.
	KeySize int
	// KeyType is the type of keys to generate.
	KeyType string
	// CAExpiry is the expiry of the CA.
	CAExpiry time.Duration
	// AdminExpiry is the expiry of the admin user.
	AdminExpiry time.Duration
}

func (o *GenerateOptions) applyDefaults() {
	if o.CAName == "" {
		o.CAName = DefaultCAName
	}
	if o.AdminName == "" {
		o.AdminName = DefaultAdminName
	}
	if o.KeySize == 0 {
		o.KeySize = DefaultKeySize
	}
	if o.KeyType == "" {
		o.KeyType = DefaultKeyType
	}
	if o.CAExpiry == 0 {
		o.CAExpiry = DefaultCAExpiry
	}
	if o.AdminExpiry == 0 {
		o.AdminExpiry = DefaultNodeExpiry
	}
}

func (o *GenerateOptions) validate() error {
	if o.KeySize < 256 {
		return fmt.Errorf("key size must be at least 256 bits")
	}
	if o.KeyType != "ecdsa" && o.KeyType != "rsa" {
		return fmt.Errorf("key type must be ecdsa or rsa")
	}
	if o.KeyType == "ecdsa" {
		if o.KeySize != 256 && o.KeySize != 384 && o.KeySize != 521 {
			return fmt.Errorf("key size must be 256, 384, or 521 for ecdsa")
		}
	}
	if o.KeyType == "rsa" {
		if o.KeySize%8 != 0 {
			return fmt.Errorf("key size must be a multiple of 8 for rsa")
		}
	}
	return nil
}

// IssueOptions are options for issuing a new certificate.
type IssueOptions struct {
	// Name is the name of the certificate.
	Name string
	// KeySize is the size of the keys to generate.
	KeySize int
	// KeyType is the type of keys to generate.
	KeyType string
	// Expiry is the expiry of the certificate.
	Expiry time.Duration
}

func (o *IssueOptions) applyDefaults() {
	if o.KeySize == 0 {
		o.KeySize = DefaultKeySize
	}
	if o.KeyType == "" {
		o.KeyType = DefaultKeyType
	}
	if o.Expiry == 0 {
		o.Expiry = DefaultNodeExpiry
	}
}

func (o *IssueOptions) validate() error {
	if o.Name == "" {
		return fmt.Errorf("name must be specified")
	}
	if o.KeySize < 256 {
		return fmt.Errorf("key size must be at least 256 bits")
	}
	if o.KeyType != "ecdsa" && o.KeyType != "rsa" {
		return fmt.Errorf("key type must be ecdsa or rsa")
	}
	if o.KeyType == "ecdsa" {
		if o.KeySize != 256 && o.KeySize != 384 && o.KeySize != 521 {
			return fmt.Errorf("key size must be 256, 384, or 521 for ecdsa")
		}
	}
	if o.KeyType == "rsa" {
		if o.KeySize%8 != 0 {
			return fmt.Errorf("key size must be a multiple of 8 for rsa")
		}
	}
	return nil
}

// GenerateConfigOptions are options for generating a new config.
type GenerateConfigOptions struct {
	// Name is the name of the certificate.
	Name string
	// Server is the server address.
	Server string
	// Output is the output file.
	Output string
	// ContextName sets the name of the context. Defaults to "default".
	ContextName string
	// ClusterName sets the name of the cluster. Defaults to "default".
	ClusterName string
	// UserName sets the name of the user. Defaults to "default".
	UserName string
}

func (o *GenerateConfigOptions) applyDefaults() {
	if o.Name == "" {
		o.Name = DefaultAdminName
	}
	if o.ContextName == "" {
		o.ContextName = "default"
	}
	if o.ClusterName == "" {
		o.ClusterName = "default"
	}
	if o.UserName == "" {
		o.UserName = "default"
	}
}

func (o *GenerateConfigOptions) validate() error {
	if o.Name == "" {
		return fmt.Errorf("name must be specified")
	}
	if o.Server == "" {
		return fmt.Errorf("server must be specified")
	}
	return nil
}

// New returns a new PKI.
func New(dir string) PKI {
	return &pki{
		dataDir: dir,
	}
}

type pki struct {
	dataDir string
}

func (p *pki) Generate(opts *GenerateOptions) error {
	opts.applyDefaults()
	if err := opts.validate(); err != nil {
		return err
	}
	// Bail out if the PKI directory already exists.
	if _, err := os.Stat(p.dataDir); err == nil {
		return fmt.Errorf("pki directory %s already exists", p.dataDir)
	} else if !os.IsNotExist(err) {
		return err
	}
	// Generate the CA and admin keys.
	var caPrivKey, caPubKey, adminPrivKey, adminPubKey any
	var err error
	switch opts.KeyType {
	case "ecdsa":
		caPrivKey, err = generateECDSAKey(opts.KeySize)
		if err != nil {
			return err
		}
		caPubKey = &caPrivKey.(*ecdsa.PrivateKey).PublicKey
		adminPrivKey, err = generateECDSAKey(opts.KeySize)
		if err != nil {
			return err
		}
		adminPubKey = &adminPrivKey.(*ecdsa.PrivateKey).PublicKey
	case "rsa":
		caPrivKey, err = rsa.GenerateKey(rand.Reader, opts.KeySize)
		if err != nil {
			return err
		}
		caPubKey = &caPrivKey.(*rsa.PrivateKey).PublicKey
		adminPrivKey, err = rsa.GenerateKey(rand.Reader, opts.KeySize)
		if err != nil {
			return err
		}
		adminPubKey = &adminPrivKey.(*rsa.PrivateKey).PublicKey
	default:
		// Should never happen.
		return fmt.Errorf("unsupported key type: %s", opts.KeyType)
	}
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(r.Int63()),
		Subject: pkix.Name{
			CommonName: opts.CAName,
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().Add(opts.CAExpiry),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, caPubKey, caPrivKey)
	if err != nil {
		return err
	}
	admin := &x509.Certificate{
		SerialNumber: big.NewInt(r.Int63()),
		Subject: pkix.Name{
			CommonName: opts.AdminName,
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().Add(opts.AdminExpiry),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	adminBytes, err := x509.CreateCertificate(rand.Reader, admin, ca, adminPubKey, caPrivKey)
	if err != nil {
		return err
	}
	// Write the CA and admin keys and certs to disk.
	err = writeCertChain(filepath.Join(p.dataDir, CADirectory), caBytes, caBytes, caPrivKey)
	if err != nil {
		return err
	}
	err = writeCertChain(filepath.Join(p.dataDir, NodesDirectory, opts.AdminName), caBytes, adminBytes, adminPrivKey)
	if err != nil {
		return err
	}
	return nil
}

func (p *pki) Issue(opts *IssueOptions) error {
	opts.applyDefaults()
	if err := opts.validate(); err != nil {
		return err
	}
	// Bail out if the PKI directory does not exist or the user exists.
	if _, err := os.Stat(p.dataDir); err != nil {
		return fmt.Errorf("pki directory %s does not exist", p.dataDir)
	}
	if _, err := os.Stat(filepath.Join(p.dataDir, NodesDirectory, opts.Name)); err == nil {
		return fmt.Errorf("user %s already exists", opts.Name)
	} else if !os.IsNotExist(err) {
		return err
	}
	// Load the CA.
	caPath := filepath.Join(p.dataDir, CADirectory)
	caCert, err := loadCert(filepath.Join(caPath, caFileName))
	if err != nil {
		return err
	}
	caPrivKey, err := loadPrivateKey(filepath.Join(caPath, keyFileName))
	if err != nil {
		return err
	}
	// Generate the key.
	var privKey, pubKey any
	switch opts.KeyType {
	case "ecdsa":
		privKey, err = generateECDSAKey(opts.KeySize)
		if err != nil {
			return err
		}
		pubKey = &privKey.(*ecdsa.PrivateKey).PublicKey
	case "rsa":
		privKey, err = rsa.GenerateKey(rand.Reader, opts.KeySize)
		if err != nil {
			return err
		}
		pubKey = &privKey.(*rsa.PrivateKey).PublicKey
	default:
		// Should never happen.
		return fmt.Errorf("unsupported key type: %s", opts.KeyType)
	}
	// Generate the certificate.
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(r.Int63()),
		Subject: pkix.Name{
			CommonName: opts.Name,
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().UTC().Add(opts.Expiry),
		IsCA:                  false,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, pubKey, caPrivKey)
	if err != nil {
		return err
	}
	// Write the key and cert to disk.
	err = writeCertChain(filepath.Join(p.dataDir, NodesDirectory, opts.Name), caCert.Raw, certBytes, privKey)
	if err != nil {
		return err
	}
	return nil
}

func (p *pki) GenerateConfig(opts *GenerateConfigOptions) error {
	opts.applyDefaults()
	if err := opts.validate(); err != nil {
		return err
	}
	caData, err := os.ReadFile(filepath.Join(p.dataDir, CADirectory, caFileName))
	if err != nil {
		return fmt.Errorf("error reading CA certificate: %w", err)
	}
	certData, err := os.ReadFile(filepath.Join(p.dataDir, NodesDirectory, opts.Name, certFileName))
	if err != nil {
		return fmt.Errorf("error reading certificate: %w", err)
	}
	keyData, err := os.ReadFile(filepath.Join(p.dataDir, NodesDirectory, opts.Name, keyFileName))
	if err != nil {
		return fmt.Errorf("error reading key: %w", err)
	}
	conf := config.New()
	conf.Clusters = append(conf.Clusters, config.Cluster{
		Name: opts.ClusterName,
		Cluster: config.ClusterConfig{
			Server:                   opts.Server,
			CertificateAuthorityData: base64.StdEncoding.EncodeToString(caData),
			TLSVerifyChainOnly:       true,
		},
	})
	conf.Users = append(conf.Users, config.User{
		Name: opts.UserName,
		User: config.UserConfig{
			ClientCertificateData: base64.StdEncoding.EncodeToString(certData),
			ClientKeyData:         base64.StdEncoding.EncodeToString(keyData),
		},
	})
	conf.Contexts = append(conf.Contexts, config.Context{
		Name: opts.ContextName,
		Context: config.ContextConfig{
			Cluster: opts.ClusterName,
			User:    opts.UserName,
		},
	})
	conf.CurrentContext = opts.ContextName
	err = conf.WriteTo(opts.Output)
	if err != nil {
		return fmt.Errorf("error writing config: %w", err)
	}
	return nil
}

func generateECDSAKey(size int) (*ecdsa.PrivateKey, error) {
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

func writeCertChain(path string, ca, cert []byte, key any) error {
	err := os.MkdirAll(path, 0755)
	if err != nil {
		return fmt.Errorf("error creating directory %s: %w", path, err)
	}
	// Encode the certificates
	caPath := filepath.Join(path, caFileName)
	caFile, err := os.Create(caPath)
	if err != nil {
		return fmt.Errorf("error creating file %s: %w", caPath, err)
	}
	defer caFile.Close()
	err = pem.Encode(caFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca,
	})
	if err != nil {
		return fmt.Errorf("error encoding certificate to %s: %w", caFile.Name(), err)
	}
	certPath := filepath.Join(path, certFileName)
	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("error creating file %s: %w", certPath, err)
	}
	defer certFile.Close()
	err = pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	if err != nil {
		return fmt.Errorf("error encoding certificate to %s: %w", certFile.Name(), err)
	}
	// Determine the key type.
	var keyType string
	var keyBytes []byte
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
	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}
	// Encode the key.
	keyPath := filepath.Join(path, keyFileName)
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("error creating file %s: %w", keyPath, err)
	}
	defer keyFile.Close()
	err = pem.Encode(keyFile, &pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	})
	if err != nil {
		return fmt.Errorf("error encoding key to %s: %w", keyFile.Name(), err)
	}
	return nil
}

func loadCert(path string) (*x509.Certificate, error) {
	certFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening file %s: %w", path, err)
	}
	defer certFile.Close()
	certBytes, err := os.ReadFile(certFile.Name())
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", certFile.Name(), err)
	}
	// Decode the PEM block.
	block, extra := pem.Decode(certBytes)
	if len(bytes.TrimSpace(extra)) != 0 {
		return nil, fmt.Errorf("unexpected extra data in %s", certFile.Name())
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate from %s: %w", certFile.Name(), err)
	}
	return cert, nil
}

func loadPrivateKey(path string) (any, error) {
	keyFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening file %s: %w", path, err)
	}
	defer keyFile.Close()
	keyBytes, err := os.ReadFile(keyFile.Name())
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", keyFile.Name(), err)
	}
	key, err := parsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key from %s: %w", keyFile.Name(), err)
	}
	return key, nil
}

func parsePrivateKey(keyBytes []byte) (any, error) {
	block, extra := pem.Decode(keyBytes)
	if len(bytes.TrimSpace(extra)) != 0 {
		return nil, fmt.Errorf("unexpected extra data in private key")
	}
	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}
}
