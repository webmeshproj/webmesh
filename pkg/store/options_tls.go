/*
Copyright 2023.

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

package store

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"

	"golang.org/x/exp/slog"

	"github.com/webmeshproj/node/pkg/util"
)

const (
	CertFileEnvVar           = "TLS_CERT_FILE"
	KeyFileEnvVar            = "TLS_KEY_FILE"
	CAFileEnvVar             = "TLS_CA_FILE"
	VerifyChainOnlyEnvVar    = "TLS_VERIFY_CHAIN_ONLY"
	InsecureSkipVerifyEnvVar = "TLS_INSECURE_SKIP_VERIFY"
	InsecureEnvVar           = "TLS_INSECURE"
)

// TLSOptions are options for TLS communication when joining a mesh.
type TLSOptions struct {
	// TLSCertFile is the path to the TLS certificate file to present when joining.
	CertFile string `yaml:"tls-cert-file,omitempty" json:"tls-cert-file,omitempty" toml:"tls-cert-file,omitempty"`
	// TLSKeyFile is the path to the TLS key file for the certificate.
	KeyFile string `yaml:"tls-key-file,omitempty" json:"tls-key-file,omitempty" toml:"tls-key-file,omitempty"`
	// TLSCAFile is the path to a TLS CA file. If empty, the system CA pool is used.
	CAFile string `yaml:"tls-ca-file,omitempty" json:"tls-ca-file,omitempty" toml:"tls-ca-file,omitempty"`
	// VerifyChainOnly is true if only the certificate chain should be verified.
	VerifyChainOnly bool `yaml:"verify-chain-only,omitempty" json:"verify-chain-only,omitempty" toml:"verify-chain-only,omitempty"`
	// InsecureSkipVerify is true if the server TLS cert should not be verified.
	InsecureSkipVerify bool `yaml:"insecure-skip-verify,omitempty" json:"insecure-skip-verify,omitempty" toml:"insecure-skip-verify,omitempty"`
	// Insecure is true if TLS should be disabled.
	Insecure bool `yaml:"insecure,omitempty" json:"insecure,omitempty" toml:"insecure,omitempty"`
}

// NewTLSOptions creates a new TLSOptions with default values.
func NewTLSOptions() *TLSOptions {
	return &TLSOptions{}
}

// TLSConfig returns the TLS configuration.
func (o *TLSOptions) TLSConfig() (*tls.Config, error) {
	if o.Insecure {
		return nil, nil
	}
	var config tls.Config
	if o.CertFile != "" && o.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load x509 key pair: %w", err)
		}
		config.Certificates = []tls.Certificate{cert}
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		slog.Default().Warn("failed to load system cert pool", slog.String("error", err.Error()))
		pool = x509.NewCertPool()
	}
	if o.CAFile != "" {
		ca, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file: %w", err)
		}
		if ok := pool.AppendCertsFromPEM(ca); !ok {
			return nil, fmt.Errorf("append certs from pem")
		}
	}
	config.RootCAs = pool
	if o.VerifyChainOnly {
		config.InsecureSkipVerify = true
		config.VerifyPeerCertificate = util.VerifyChainOnly
	} else if o.InsecureSkipVerify {
		config.InsecureSkipVerify = true
	}
	return &config, nil
}

// BindFlags binds the TLS options to the flag set.
func (o *TLSOptions) BindFlags(fl *flag.FlagSet) {
	fl.StringVar(&o.CertFile, "tls.cert-file", util.GetEnvDefault(CertFileEnvVar, ""),
		"Stream layer TLS certificate file.")
	fl.StringVar(&o.KeyFile, "tls.key-file", util.GetEnvDefault(KeyFileEnvVar, ""),
		"Stream layer TLS key file.")
	fl.StringVar(&o.CAFile, "tls.ca-file", util.GetEnvDefault(CAFileEnvVar, ""),
		"Stream layer TLS CA file.")
	fl.BoolVar(&o.VerifyChainOnly, "tls.verify-chain-only", util.GetEnvDefault(VerifyChainOnlyEnvVar, "false") == "true",
		"Only verify the certificate chain for the stream layer.")
	fl.BoolVar(&o.InsecureSkipVerify, "tls.insecure-skip-verify", util.GetEnvDefault(InsecureSkipVerifyEnvVar, "false") == "true",
		"Skip verification of the stream layer certificate.")
	fl.BoolVar(&o.Insecure, "tls.insecure", util.GetEnvDefault(InsecureEnvVar, "false") == "true",
		"Don't use TLS for the stream layer.")
}
