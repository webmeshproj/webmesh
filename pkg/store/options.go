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
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"

	"golang.org/x/exp/slog"

	"github.com/webmeshproj/node/pkg/plugins"
	"github.com/webmeshproj/node/pkg/util"
)

// Options are the options for the store.
type Options struct {
	// Auth are options for authentication to the mesh.
	Auth *AuthOptions `json:"auth,omitempty" yaml:"auth,omitempty" toml:"auth,omitempty"`
	// Mesh are options for participating in an existing mesh.
	Mesh *MeshOptions `json:"mesh,omitempty" yaml:"mesh,omitempty" toml:"mesh,omitempty"`
	// Bootstrap are options for bootstrapping the store.
	Bootstrap *BootstrapOptions `json:"bootstrap,omitempty" yaml:"bootstrap,omitempty" toml:"bootstrap,omitempty"`
	// Raft are options for the raft store.
	Raft *RaftOptions `json:"raft,omitempty" yaml:"raft,omitempty" toml:"raft,omitempty"`
	// TLS are options for TLS.
	TLS *TLSOptions `json:"tls,omitempty" yaml:"tls,omitempty" toml:"tls,omitempty"`
	// WireGuard are options for WireGuard.
	WireGuard *WireGuardOptions `json:"wireguard,omitempty" yaml:"wireguard,omitempty" toml:"wireguard,omitempty"`
	// Plugins are options for plugins.
	Plugins *plugins.Options `yaml:"plugins,omitempty" json:"plugins,omitempty" toml:"plugins,omitempty"`
}

// NewOptions returns new options with sensible defaults.
func NewOptions() *Options {
	return &Options{
		Auth:      NewAuthOptions(),
		Mesh:      NewMeshOptions(),
		Bootstrap: NewBootstrapOptions(),
		Raft:      NewRaftOptions(),
		TLS:       NewTLSOptions(),
		WireGuard: NewWireGuardOptions(),
		Plugins:   plugins.NewOptions(),
	}
}

// BindFlags binds the options to the flags.
func (o *Options) BindFlags(fl *flag.FlagSet) {
	o.Auth.BindFlags(fl)
	o.Mesh.BindFlags(fl)
	o.Bootstrap.BindFlags(fl)
	o.Raft.BindFlags(fl)
	o.TLS.BindFlags(fl)
	o.WireGuard.BindFlags(fl)
	o.Plugins.BindFlags(fl)
}

// Validate validates the options.
func (o *Options) Validate() error {
	if o.Raft == nil {
		o.Raft = NewRaftOptions()
	}
	if o.Mesh == nil {
		o.Mesh = NewMeshOptions()
	}
	if o.Bootstrap == nil {
		o.Bootstrap = NewBootstrapOptions()
	}
	if o.TLS == nil {
		o.TLS = NewTLSOptions()
	}
	if o.WireGuard == nil {
		o.WireGuard = NewWireGuardOptions()
	}
	if err := o.Auth.Validate(); err != nil {
		return err
	}
	if err := o.Mesh.Validate(); err != nil {
		return err
	}
	if err := o.Raft.Validate(); err != nil {
		return err
	}
	if err := o.Bootstrap.Validate(); err != nil {
		return err
	}
	if err := o.WireGuard.Validate(); err != nil {
		return err
	}
	return nil
}

// TLSConfig returns the TLS configuration.
func (o *Options) TLSConfig() (*tls.Config, error) {
	if o.TLS == nil || o.TLS.Insecure {
		return nil, nil
	}
	var config tls.Config
	if o.Auth != nil && o.Auth.MTLS != nil {
		if o.Auth.MTLS.CertFile != "" && o.Auth.MTLS.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(o.Auth.MTLS.CertFile, o.Auth.MTLS.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("load x509 key pair: %w", err)
			}
			config.Certificates = []tls.Certificate{cert}
		}
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		slog.Default().Warn("failed to load system cert pool", slog.String("error", err.Error()))
		pool = x509.NewCertPool()
	}
	if o.TLS.CAFile != "" {
		ca, err := os.ReadFile(o.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file: %w", err)
		}
		if ok := pool.AppendCertsFromPEM(ca); !ok {
			return nil, fmt.Errorf("append certs from pem")
		}
	}
	config.RootCAs = pool
	if o.TLS.VerifyChainOnly {
		config.InsecureSkipVerify = true
		config.VerifyPeerCertificate = util.VerifyChainOnly
	} else if o.TLS.InsecureSkipVerify {
		config.InsecureSkipVerify = true
	}
	return &config, nil
}
