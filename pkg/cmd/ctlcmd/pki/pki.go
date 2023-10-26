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
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/webmeshproj/webmesh/pkg/cmd/ctlcmd/config"
	"github.com/webmeshproj/webmesh/pkg/crypto"
)

const (
	// DefaultCAName is the default CA name.
	DefaultCAName = "webmesh-ca"
	// DefaultKeyType is the default key type.
	DefaultKeyType = crypto.TLSKeyECDSA
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
	// Init generates a new PKI.
	Init(InitOptions) error
	// Issue issues a new certificate.
	Issue(IssueOptions) error
	// GenerateConfig generates a new config.
	GenerateConfig(GenerateConfigOptions) error
}

// InitOptions are options for generating a new PKI.
type InitOptions struct {
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

func (o *InitOptions) applyDefaults() {
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
		o.KeyType = string(DefaultKeyType)
	}
	if o.CAExpiry == 0 {
		o.CAExpiry = DefaultCAExpiry
	}
	if o.AdminExpiry == 0 {
		o.AdminExpiry = DefaultNodeExpiry
	}
}

func (o *InitOptions) validate() error {
	if o.KeySize < 256 {
		return fmt.Errorf("key size must be at least 256 bits")
	}
	if !crypto.TLSKeyType(o.KeyType).IsValid() {
		return fmt.Errorf("key type must be ecdsa, rsa, or webmesh")
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
		o.KeyType = string(DefaultKeyType)
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
	if !crypto.TLSKeyType(o.KeyType).IsValid() {
		return fmt.Errorf("key type must be ecdsa, rsa, or webmesh")
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

func (p *pki) Init(opts InitOptions) error {
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
	// Generate CA cert and key.
	caPrivKey, caCert, err := crypto.GenerateCA(crypto.CACertConfig{
		CommonName: opts.CAName,
		ValidFor:   opts.CAExpiry,
		KeyType:    crypto.TLSKeyType(opts.KeyType),
		KeySize:    opts.KeySize,
	})
	if err != nil {
		return err
	}
	// Issue an admin certificate using the CA.
	adminPrivKey, adminCert, err := crypto.IssueCertificate(crypto.IssueConfig{
		CommonName: opts.CAName,
		ValidFor:   opts.CAExpiry,
		KeyType:    crypto.TLSKeyType(opts.KeyType),
		KeySize:    opts.KeySize,
		CACert:     caCert,
		CAKey:      caPrivKey,
	})
	if err != nil {
		return err
	}
	// Write the CA and admin keys and certs to disk.
	err = writeCertChain(filepath.Join(p.dataDir, CADirectory), caCert, caCert, caPrivKey)
	if err != nil {
		return err
	}
	err = writeCertChain(filepath.Join(p.dataDir, NodesDirectory, opts.AdminName), caCert, adminCert, adminPrivKey)
	if err != nil {
		return err
	}
	return nil
}

func (p *pki) Issue(opts IssueOptions) error {
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
	caCert, err := crypto.DecodeTLSCertificateFromFile(filepath.Join(caPath, caFileName))
	if err != nil {
		return err
	}
	caPrivKey, err := crypto.DecodeTLSPrivateKeyFromFile(filepath.Join(caPath, keyFileName))
	if err != nil {
		return err
	}
	privkey, cert, err := crypto.IssueCertificate(crypto.IssueConfig{
		CommonName: opts.Name,
		ValidFor:   opts.Expiry,
		KeyType:    crypto.TLSKeyType(opts.KeyType),
		KeySize:    opts.KeySize,
		CACert:     caCert,
		CAKey:      caPrivKey,
	})
	if err != nil {
		return err
	}
	// Write the key and cert to disk.
	err = writeCertChain(filepath.Join(p.dataDir, NodesDirectory, opts.Name), caCert, cert, privkey)
	if err != nil {
		return err
	}
	return nil
}

func (p *pki) GenerateConfig(opts GenerateConfigOptions) error {
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

func writeCertChain(path string, ca, cert *crypto.TLSCertificate, key crypto.StdPrivateKey) error {
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
	err = crypto.EncodeTLSCertificate(caFile, ca)
	if err != nil {
		return fmt.Errorf("error encoding CA certificate to %s: %w", caFile.Name(), err)
	}
	certPath := filepath.Join(path, certFileName)
	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("error creating file %s: %w", certPath, err)
	}
	defer certFile.Close()
	// Encode the certificate.
	err = crypto.EncodeTLSCertificate(certFile, cert)
	if err != nil {
		return fmt.Errorf("error encoding certificate to %s: %w", certFile.Name(), err)
	}
	// Encode the CA again as the issuer.
	err = crypto.EncodeTLSCertificate(certFile, ca)
	if err != nil {
		return fmt.Errorf("error encoding certificate to %s: %w", certFile.Name(), err)
	}
	// Encode the key.
	keyPath := filepath.Join(path, keyFileName)
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("error creating file %s: %w", keyPath, err)
	}
	defer keyFile.Close()
	err = crypto.EncodeTLSPrivateKey(keyFile, key)
	if err != nil {
		return fmt.Errorf("error encoding key to %s: %w", keyFile.Name(), err)
	}
	return nil
}
