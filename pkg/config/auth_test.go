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
	"testing"

	"github.com/spf13/pflag"
)

func TestAuthConfigValidate(t *testing.T) {
	t.Parallel()
	tc := []struct {
		name     string
		authOpts *AuthOptions
		wantErr  bool
	}{
		{
			name:     "NilOptions",
			authOpts: nil,
			wantErr:  false,
		},
		{
			name:     "EmptyOptions",
			authOpts: &AuthOptions{},
			wantErr:  false,
		},
		{
			name: "MTLSMissingCertFile",
			authOpts: &AuthOptions{
				MTLS: MTLSOptions{
					KeyFile: "keyfile",
				},
			},
			wantErr: true,
		},
		{
			name: "MTLSMissingCertData",
			authOpts: &AuthOptions{
				MTLS: MTLSOptions{
					KeyData: "keydata",
				},
			},
			wantErr: true,
		},
		{
			name: "MTLSMissingKeyFile",
			authOpts: &AuthOptions{
				MTLS: MTLSOptions{
					CertFile: "keyfile",
				},
			},
			wantErr: true,
		},
		{
			name: "MTLSMissingKeyData",
			authOpts: &AuthOptions{
				MTLS: MTLSOptions{
					CertData: "keydata",
				},
			},
			wantErr: true,
		},
		{
			name: "MTLSCertAndKeyFiles",
			authOpts: &AuthOptions{
				MTLS: MTLSOptions{
					KeyFile:  "keyfile",
					CertFile: "certfile",
				},
			},
			wantErr: false,
		},
		{
			name: "MTLSCertAndKeyData",
			authOpts: &AuthOptions{
				MTLS: MTLSOptions{
					KeyData:  "keydata",
					CertData: "certdata",
				},
			},
			wantErr: false,
		},
		{
			name: "BasicMissingUsername",
			authOpts: &AuthOptions{
				Basic: BasicAuthOptions{
					Password: "password",
				},
			},
			wantErr: true,
		},
		{
			name: "BasicMissingPassword",
			authOpts: &AuthOptions{
				Basic: BasicAuthOptions{
					Username: "username",
				},
			},
			wantErr: true,
		},
		{
			name: "BasicValidOptions",
			authOpts: &AuthOptions{
				Basic: BasicAuthOptions{
					Username: "username",
					Password: "password",
				},
			},
			wantErr: false,
		},
		{
			name: "LDAPMissingUsername",
			authOpts: &AuthOptions{
				LDAP: LDAPAuthOptions{
					Password: "password",
				},
			},
			wantErr: true,
		},
		{
			name: "LDAPMissingPassword",
			authOpts: &AuthOptions{
				LDAP: LDAPAuthOptions{
					Username: "username",
				},
			},
			wantErr: true,
		},
		{
			name: "LDAPValidOptions",
			authOpts: &AuthOptions{
				LDAP: LDAPAuthOptions{
					Username: "username",
					Password: "password",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			// Make sure binding the auth flags to a flag set doesn't panic
			if tt.authOpts != nil {
				fs := pflag.NewFlagSet("test", pflag.PanicOnError)
				tt.authOpts.BindFlags("test", fs)
			}
			// Run the test case
			err := tt.authOpts.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("AuthOptions.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && err != nil {
				t.Errorf("AuthOptions.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
