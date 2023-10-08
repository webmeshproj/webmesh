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

func TestGlobalOptionsValidate(t *testing.T) {
	t.Parallel()
	defaults := NewGlobalOptions()
	tc := []struct {
		name    string
		opts    *GlobalOptions
		wantErr bool
	}{
		{
			name:    "NilOptions",
			opts:    nil,
			wantErr: false,
		},
		{
			name:    "Defaults",
			opts:    &defaults,
			wantErr: false,
		},
		{
			name: "InvalidIPPreferences",
			opts: &GlobalOptions{
				DisableIPv4: true,
				DisableIPv6: true,
			},
			wantErr: true,
		},
		{
			name: "MTLSNoCertFile",
			opts: &GlobalOptions{
				MTLS:        true,
				TLSCertFile: "",
				TLSKeyFile:  "keyfile",
				TLSCAFile:   "cafile",
			},
			wantErr: true,
		},
		{
			name: "MTLSNoKeyFile",
			opts: &GlobalOptions{
				MTLS:        true,
				TLSCertFile: "certfile",
				TLSKeyFile:  "",
				TLSCAFile:   "cafile",
			},
			wantErr: true,
		},
		{
			name: "MTLSNoCAFile",
			opts: &GlobalOptions{
				MTLS:        true,
				TLSCertFile: "certfile",
				TLSKeyFile:  "keyfile",
				TLSCAFile:   "",
			},
			wantErr: true,
		},
		{
			name: "MTLSValid",
			opts: &GlobalOptions{
				MTLS:        true,
				TLSCertFile: "certfile",
				TLSKeyFile:  "keyfile",
				TLSCAFile:   "cafile",
			},
			wantErr: false,
		},
	}
	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			if tt.opts != nil {
				// Make sure they bind to a flagset without error
				fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
				tt.opts.BindFlags(fs)
			}
			if err := tt.opts.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("GlobalOptions.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestApplyGlobalOptions(t *testing.T) {
	t.Parallel()
}
