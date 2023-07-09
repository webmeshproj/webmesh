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

package store

import (
	"flag"

	"github.com/webmeshproj/node/pkg/util"
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
	CAFile string `yaml:"tls-ca-file,omitempty" json:"tls-ca-file,omitempty" toml:"tls-ca-file,omitempty"`
	// CAData is the base64 encoded TLS CA data for verification. If this and CAFile are empty, the system CA pool is used.
	CAData string `yaml:"tls-ca-data,omitempty" json:"tls-ca-data,omitempty" toml:"tls-ca-data,omitempty"`
	// VerifyChainOnly is true if only the certificate chain should be verified.
	VerifyChainOnly bool `yaml:"verify-chain-only,omitempty" json:"verify-chain-only,omitempty" toml:"verify-chain-only,omitempty"`
	// InsecureSkipVerify is true if the server TLS cert should not be verified.
	InsecureSkipVerify bool `yaml:"insecure-skip-verify,omitempty" json:"insecure-skip-verify,omitempty" toml:"insecure-skip-verify,omitempty"`
	// Insecure is true if the gRPC connection should be insecure.
	Insecure bool `yaml:"insecure,omitempty" json:"insecure,omitempty" toml:"insecure,omitempty"`
}

// NewTLSOptions creates a new TLSOptions with default values.
func NewTLSOptions() *TLSOptions {
	return &TLSOptions{}
}

// BindFlags binds the TLS options to the flag set.
func (o *TLSOptions) BindFlags(fl *flag.FlagSet) {
	fl.StringVar(&o.CAFile, "tls.ca-file", util.GetEnvDefault(CAFileEnvVar, ""),
		"Stream layer TLS CA file.")
	fl.BoolVar(&o.VerifyChainOnly, "tls.verify-chain-only", util.GetEnvDefault(VerifyChainOnlyEnvVar, "false") == "true",
		"Only verify the certificate chain for the stream layer.")
	fl.BoolVar(&o.InsecureSkipVerify, "tls.insecure-skip-verify", util.GetEnvDefault(InsecureSkipVerifyEnvVar, "false") == "true",
		"Skip verification of the stream layer certificate.")
	fl.BoolVar(&o.Insecure, "tls.insecure", util.GetEnvDefault(InsecureEnvVar, "false") == "true",
		"Don't use TLS for the stream layer.")
}
