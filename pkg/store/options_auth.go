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
	"errors"
	"flag"
)

const (
	AuthBasicEnabledEnvVar  = "AUTH_BASIC_ENABLED"
	AuthBasicUsernameEnvVar = "AUTH_BASIC_USERNAME"
	AuthBasicPasswordEnvVar = "AUTH_BASIC_PASSWORD"
	MTLSEnabledEnvVar       = "AUTH_MTLS_ENABLED"
	MTLSKeyFileEnvVar       = "AUTH_MTLS_KEY_FILE"
	MTLSCertFileEnvVar      = "AUTH_MTLS_CERT_FILE"
)

// AuthOptions are options for authentication.
type AuthOptions struct {
	// Basic are options for basic authentication.
	Basic *BasicAuthOptions `json:"basic,omitempty" yaml:"basic,omitempty" toml:"basic,omitempty"`
	// MTLS are options for mutual TLS.
	MTLS *MTLSOptions `json:"mtls,omitempty" yaml:"mtls,omitempty" toml:"mtls,omitempty"`
}

// MTLSOptions are options for mutual TLS.
type MTLSOptions struct {
	// TLSCertFile is the path to a TLS certificate file to present when joining.
	CertFile string `yaml:"cert-file,omitempty" json:"cert-file,omitempty" toml:"cert-file,omitempty"`
	// TLSKeyFile is the path to a TLS key file for the certificate.
	KeyFile string `yaml:"key-file,omitempty" json:"key-file,omitempty" toml:"tls-file,omitempty"`
}

// BasicAuthOptions are options for basic authentication.
type BasicAuthOptions struct {
	// Username is the username.
	Username string `json:"username,omitempty" yaml:"username,omitempty" toml:"username,omitempty"`
	// Password is the password.
	Password string `json:"password,omitempty" yaml:"password,omitempty" toml:"password,omitempty"`
}

// NewAuthOptions creates a new AuthOptions.
func NewAuthOptions() *AuthOptions {
	return &AuthOptions{}
}

// BindFlags binds the flags to the options.
func (o *AuthOptions) BindFlags(fl *flag.FlagSet) {
	fl.Func("auth.mtls.cert-file", "The path to a TLS certificate file to present when joining.", func(s string) error {
		if o.MTLS == nil {
			o.MTLS = &MTLSOptions{}
		}
		o.MTLS.CertFile = s
		return nil
	})
	fl.Func("auth.mtls.key-file", "The path to a TLS key file for the certificate.", func(s string) error {
		if o.MTLS == nil {
			o.MTLS = &MTLSOptions{}
		}
		o.MTLS.KeyFile = s
		return nil
	})
	fl.Func("auth.basic.username", "A username to use for basic auth.", func(s string) error {
		if o.Basic == nil {
			o.Basic = &BasicAuthOptions{}
		}
		o.Basic.Username = s
		return nil
	})
	fl.Func("auth.basic.password", "A password to use for basic auth.", func(s string) error {
		if o.Basic == nil {
			o.Basic = &BasicAuthOptions{}
		}
		o.Basic.Password = s
		return nil
	})
}

func (o *AuthOptions) Validate() error {
	if o == nil {
		return nil
	}
	if o.MTLS != nil {
		if o.MTLS.CertFile == "" {
			return errors.New("auth.mtls.cert-file is required")
		}
		if o.MTLS.KeyFile == "" {
			return errors.New("auth.mtls.key-file is required")
		}
	}
	if o.Basic != nil {
		if o.Basic.Username == "" {
			return errors.New("auth.basic.username is required")
		}
		if o.Basic.Password == "" {
			return errors.New("auth.basic.password is required")
		}
	}
	return nil
}
