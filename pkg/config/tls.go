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

package config

import "github.com/spf13/pflag"

// TLSOptions are options for TLS communication when joining a mesh.
type TLSOptions struct {
	// CAFile is the path to a TLS CA file for verification. If this and CAData are empty, the system CA pool is used.
	CAFile string `koanf:"tls-ca-file,omitempty"`
	// CAData is the base64 encoded TLS CA data for verification. If this and CAFile are empty, the system CA pool is used.
	CAData string `koanf:"tls-ca-data,omitempty"`
	// VerifyChainOnly is true if only the certificate chain should be verified.
	VerifyChainOnly bool `koanf:"verify-chain-only,omitempty"`
	// InsecureSkipVerify is true if the server TLS cert should not be verified.
	InsecureSkipVerify bool `koanf:"insecure-skip-verify,omitempty"`
	// Insecure is true if the gRPC connection should be insecure.
	Insecure bool `koanf:"insecure,omitempty"`
}

// BindFlags binds the TLS options to the flag set.
func (o *TLSOptions) BindFlags(prefix string, fl *pflag.FlagSet) {
	fl.StringVar(&o.CAFile, prefix+"tls.ca-file", "", "Path to a TLS CA certificate for verifying peer certificates.")
	fl.StringVar(&o.CAData, prefix+"tls.ca-data", "", "Base64 encoded TLS CA certificate for verifying peer certificates.")
	fl.BoolVar(&o.VerifyChainOnly, prefix+"tls.verify-chain-only", false, "Verify only the certificate chain.")
	fl.BoolVar(&o.InsecureSkipVerify, prefix+"tls.insecure-skip-verify", false, "Skip verification of the server TLS cert.")
	fl.BoolVar(&o.Insecure, prefix+"tls.insecure", false, "Disable TLS.")
}
