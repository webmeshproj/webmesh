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

import (
	"errors"
	"fmt"

	"github.com/spf13/pflag"
)

// AuthOptions are options for authentication into the mesh.
type AuthOptions struct {
	// IDAuth indicates to use ID authentication. An ID is derived
	// from the public wireguard key and presented with a signature
	// that can be verified by the private wireguard key.
	IDAuth IDAuthOptions `koanf:"id-auth,omitempty"`
	// MTLS are options for mutual TLS. This is the recommended
	// authentication method.
	MTLS MTLSOptions `koanf:"mtls,omitempty"`
	// Basic are options for basic authentication.
	Basic BasicAuthOptions `koanf:"basic,omitempty"`
	// LDAP are options for LDAP authentication.
	LDAP LDAPAuthOptions `koanf:"ldap,omitempty"`
}

// NewAuthOptions returns a new empty AuthOptions.
func NewAuthOptions() AuthOptions {
	return AuthOptions{}
}

// IsEmpty returns true if the options are empty.
func (o *AuthOptions) IsEmpty() bool {
	if o == nil {
		return true
	}
	return o.IDAuth.IsEmpty() && o.MTLS.IsEmpty() && o.Basic.IsEmpty() && o.LDAP.IsEmpty()
}

// MTLSEnabled is true if any mtls fields are set.
func (o *AuthOptions) MTLSEnabled() bool {
	if o == nil {
		return false
	}
	return o.MTLS.Enabled()
}

// IDAuthOptions are options for ID authentication.
type IDAuthOptions struct {
	// Enabled is true if ID authentication is enabled.
	Enabled bool `koanf:"enabled,omitempty"`
	// Alias is an optional alias to attempt to register with our ID.
	// If empty, no registration will be attempted. If alias registration
	// fails it will be logged and the node will continue to run.
	Alias string `koanf:"alias,omitempty"`
	// Registrar is the registrar to attempt to use to register with our ID.
	// If left unset and an alias is provided, the node will attempt to discover
	// one via the mesh.
	// TODO: Credentials for non-mesh registrars.
	Registrar string `koanf:"registrar,omitempty"`
}

// IsEmpty returns true if the options are empty.
func (o *IDAuthOptions) IsEmpty() bool {
	return !o.Enabled
}

// MTLSOptions are options for mutual TLS.
type MTLSOptions struct {
	// CertFile is the path to a TLS certificate file to present when joining. Either this
	// or CertData must be set.
	CertFile string `koanf:"cert-file,omitempty"`
	// CertData is the base64 encoded TLS certificate data to present when joining. Either this
	// or CertFile must be set.
	CertData string `koanf:"cert-data,omitempty"`
	// KeyFile is the path to a TLS key file for the certificate. Either this or KeyData must be set.
	KeyFile string `koanf:"key-file,omitempty"`
	// KeyData is the base64 encoded TLS key data for the certificate. Either this or KeyFile must be set.
	KeyData string `koanf:"key-data,omitempty"`
}

// IsEmpty returns true if the options are empty.
func (o *MTLSOptions) IsEmpty() bool {
	return o.CertFile == "" && o.CertData == "" && o.KeyFile == "" && o.KeyData == ""
}

// Enabled is true if any fields are set.
func (o *MTLSOptions) Enabled() bool {
	return !o.IsEmpty()
}

// BasicAuthOptions are options for basic authentication.
type BasicAuthOptions struct {
	// Username is the username.
	Username string `koanf:"username,omitempty"`
	// Password is the password.
	Password string `koanf:"password,omitempty"`
}

// IsEmpty returns true if the options are empty.
func (o *BasicAuthOptions) IsEmpty() bool {
	return o.Username == "" && o.Password == ""
}

// LDAPAuthOptions are options for LDAP authentication.
type LDAPAuthOptions struct {
	// Username is the username.
	Username string `koanf:"username,omitempty"`
	// Password is the password.
	Password string `koanf:"password,omitempty"`
}

// IsEmpty returns true if the options are empty.
func (o *LDAPAuthOptions) IsEmpty() bool {
	return o.Username == "" && o.Password == ""
}

// BindFlags binds the flags to the options.
func (o *AuthOptions) BindFlags(prefix string, fl *pflag.FlagSet) {
	fl.BoolVar(&o.IDAuth.Enabled, prefix+"id-auth.enabled", o.IDAuth.Enabled, "Enable ID authentication.")
	fl.StringVar(&o.IDAuth.Alias, prefix+"id-auth.alias", o.IDAuth.Alias, "Alias to attempt to register with our ID.")
	fl.StringVar(&o.Basic.Username, prefix+"basic.username", o.Basic.Username, "Basic auth username.")
	fl.StringVar(&o.Basic.Password, prefix+"basic.password", o.Basic.Password, "Basic auth password.")
	fl.StringVar(&o.MTLS.CertFile, prefix+"mtls.cert-file", o.MTLS.CertFile, "Path to a TLS certificate file to present when joining.")
	fl.StringVar(&o.MTLS.CertData, prefix+"mtls.cert-data", o.MTLS.CertData, "Base64 encoded TLS certificate data to present when joining.")
	fl.StringVar(&o.MTLS.KeyFile, prefix+"mtls.key-file", o.MTLS.KeyFile, "Path to a TLS key file for the certificate.")
	fl.StringVar(&o.MTLS.KeyData, prefix+"mtls.key-data", o.MTLS.KeyData, "Base64 encoded TLS key data for the certificate.")
	fl.StringVar(&o.LDAP.Username, prefix+"ldap.username", o.LDAP.Username, "LDAP auth username.")
	fl.StringVar(&o.LDAP.Password, prefix+"ldap.password", o.LDAP.Password, "LDAP auth password.")
}

func (o *AuthOptions) Validate() error {
	if o.IsEmpty() {
		return nil
	}
	if !o.IDAuth.IsEmpty() {
		return nil
	}
	if !o.MTLS.IsEmpty() {
		if o.MTLS.CertFile == "" && o.MTLS.CertData == "" {
			return errors.New("auth.mtls.cert-file is required")
		}
		if o.MTLS.KeyFile == "" && o.MTLS.KeyData == "" {
			return errors.New("auth.mtls.key-file is required")
		}
		return nil
	}
	if !o.Basic.IsEmpty() {
		if o.Basic.Username == "" {
			return errors.New("auth.basic.username is required")
		}
		if o.Basic.Password == "" {
			return errors.New("auth.basic.password is required")
		}
		return nil
	}
	if !o.LDAP.IsEmpty() {
		if o.LDAP.Username == "" {
			return errors.New("auth.ldap.username is required")
		}
		if o.LDAP.Password == "" {
			return errors.New("auth.ldap.password is required")
		}
		return nil
	}
	// Something weird happened
	return fmt.Errorf("auth options are invalid: %+v", o)
}
