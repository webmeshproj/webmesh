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

package mesh

import (
	"flag"
	"strings"

	"github.com/webmeshproj/webmesh/pkg/util/envutil"
)

const (
	CAFileEnvVar             = "TLS_CA_FILE"
	VerifyChainOnlyEnvVar    = "TLS_VERIFY_CHAIN_ONLY"
	InsecureSkipVerifyEnvVar = "TLS_INSECURE_SKIP_VERIFY"
	InsecureEnvVar           = "TLS_INSECURE"
)

// TLSOptions are options for TLS communication when joining a mesh.
type TLSOptions struct {
	// CAFile is the path to a TLS CA file for verification. If this and CAData are empty, the system CA pool is used.
	CAFile string `yaml:"tls-ca-file,omitempty" json:"tls-ca-file,omitempty" toml:"tls-ca-file,omitempty" mapstructure:"tls-ca-file,omitempty"`
	// CAData is the base64 encoded TLS CA data for verification. If this and CAFile are empty, the system CA pool is used.
	CAData string `yaml:"tls-ca-data,omitempty" json:"tls-ca-data,omitempty" toml:"tls-ca-data,omitempty" mapstructure:"tls-ca-data,omitempty"`
	// VerifyChainOnly is true if only the certificate chain should be verified.
	VerifyChainOnly bool `yaml:"verify-chain-only,omitempty" json:"verify-chain-only,omitempty" toml:"verify-chain-only,omitempty" mapstructure:"verify-chain-only,omitempty"`
	// InsecureSkipVerify is true if the server TLS cert should not be verified.
	InsecureSkipVerify bool `yaml:"insecure-skip-verify,omitempty" json:"insecure-skip-verify,omitempty" toml:"insecure-skip-verify,omitempty" mapstructure:"insecure-skip-verify,omitempty"`
	// Insecure is true if the gRPC connection should be insecure.
	Insecure bool `yaml:"insecure,omitempty" json:"insecure,omitempty" toml:"insecure,omitempty" mapstructure:"insecure,omitempty"`
}

// NewTLSOptions creates a new TLSOptions with default values.
func NewTLSOptions() *TLSOptions {
	return &TLSOptions{}
}

// BindFlags binds the TLS options to the flag set.
func (o *TLSOptions) BindFlags(fl *flag.FlagSet, prefix ...string) {
	var p string
	if len(prefix) > 0 {
		p = strings.Join(prefix, ".") + "."
	}
	fl.StringVar(&o.CAFile, p+"tls.ca-file", envutil.GetEnvDefault(CAFileEnvVar, ""),
		"Path to a TLS CA certificate for verifying peer certificates.")
	fl.BoolVar(&o.VerifyChainOnly, p+"tls.verify-chain-only", envutil.GetEnvDefault(VerifyChainOnlyEnvVar, "false") == "true",
		"Only verify the certificate chain of peer certificates.")
	fl.BoolVar(&o.InsecureSkipVerify, p+"tls.insecure-skip-verify", envutil.GetEnvDefault(InsecureSkipVerifyEnvVar, "false") == "true",
		"Skip verification of peer certificates.")
	fl.BoolVar(&o.Insecure, p+"tls.insecure", envutil.GetEnvDefault(InsecureEnvVar, "false") == "true",
		"Don't use TLS for peer communication.")
}

// DeepCopy returns a deep copy of the TLSOptions.
func (o *TLSOptions) DeepCopy() *TLSOptions {
	if o == nil {
		return nil
	}
	return &TLSOptions{
		CAFile:             o.CAFile,
		CAData:             o.CAData,
		VerifyChainOnly:    o.VerifyChainOnly,
		InsecureSkipVerify: o.InsecureSkipVerify,
		Insecure:           o.Insecure,
	}
}
