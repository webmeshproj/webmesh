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

// Package options contains configuration parsing for the nodecmd.
package config

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/spf13/pflag"
)

// DefaultNodeID is the default node ID used if no other is configured
var DefaultNodeID = func() string {
	hostname, err := os.Hostname()
	if err != nil {
		return uuid.NewString()
	}
	return hostname
}()

// Config are the configuration options for running a webmesh node.
type Config struct {
	// Global are global options that are overlaid on all other options.
	Global GlobalOptions `koanf:"global,omitempty"`
	// Bootstrap are the bootstrap options.
	Bootstrap BootstrapOptions `koanf:"bootstrap,omitempty"`
	// Auth are the authentication options.
	Auth AuthOptions `koanf:"auth,omitempty"`
	// Mesh are the mesh options.
	Mesh MeshOptions `koanf:"mesh,omitempty"`
	// Raft are the raft options.
	Raft RaftOptions `koanf:"raft,omitempty"`
	// Services are the service options.
	Services ServiceOptions `koanf:"services,omitempty"`
	// TLS are the TLS options.
	TLS TLSOptions `koanf:"tls,omitempty"`
	// WireGuard are the WireGuard options.
	WireGuard WireGuardOptions `koanf:"wireguard,omitempty"`
	// Discovery are the discovery options.
	Discovery DiscoveryOptions `koanf:"discovery,omitempty"`
	// Plugins are the plugin options.
	Plugins PluginOptions `koanf:"plugins,omitempty"`
	// Bridge are the bridge options.
	Bridge BridgeOptions `koanf:"bridge,omitempty"`
}

// BindFlags binds the flags. The options are returned for convenience.
func (o *Config) BindFlags(prefix string, fs *pflag.FlagSet) *Config {
	o.Global.BindFlags(fs)
	o.Bootstrap.BindFlags(prefix, fs)
	o.Auth.BindFlags(prefix, fs)
	o.Mesh.BindFlags(prefix, fs)
	o.Raft.BindFlags(prefix, fs)
	o.Services.BindFlags(prefix, fs)
	o.TLS.BindFlags(prefix, fs)
	o.WireGuard.BindFlags(prefix, fs)
	o.Discovery.BindFlags(prefix, fs)
	o.Plugins.BindFlags(prefix, fs)
	// Don't recurse on bridge configurations
	if prefix == "" {
		o.Bridge.BindFlags(fs)
	}
	return o
}

// ErrNoMesh is returned when no mesh is configured to be bootstrapped or joined.
var ErrNoMesh = fmt.Errorf("no mesh configured")

// Validate validates the configuration.
func (o *Config) Validate() error {
	// Make sure we are either bootstrapping or joining a mesh
	if !o.Bootstrap.Enabled && o.Mesh.JoinAddress == "" && (!o.Discovery.UseKadDHT && o.Discovery.PSK == "") {
		return ErrNoMesh
	}
	err := o.Global.Validate()
	if err != nil {
		return fmt.Errorf("invalid global options: %w", err)
	}
	if o.Bootstrap.Enabled {
		err := o.Bootstrap.Validate()
		if err != nil {
			return fmt.Errorf("invalid bootstrap options: %w", err)
		}
	}
	err = o.Auth.Validate()
	if err != nil {
		return fmt.Errorf("invalid auth options: %w", err)
	}
	err = o.Mesh.Validate()
	if err != nil {
		return fmt.Errorf("invalid mesh options: %w", err)
	}
	if o.IsRaftMember() {
		err := o.Raft.Validate()
		if err != nil {
			return fmt.Errorf("invalid raft options: %w", err)
		}
	}
	err = o.Services.Validate()
	if err != nil {
		return fmt.Errorf("invalid service options: %w", err)
	}
	err = o.WireGuard.Validate()
	if err != nil {
		return fmt.Errorf("invalid wireguard options: %w", err)
	}
	err = o.Discovery.Validate()
	if err != nil {
		return fmt.Errorf("invalid discovery options: %w", err)
	}
	err = o.Bridge.Validate()
	if err != nil {
		return fmt.Errorf("invalid bridge options: %w", err)
	}
	return nil
}

// NodeID returns the node ID for this configuration, or any error attempting to determine it.
func (o *Config) NodeID() (string, error) {
	if o.Mesh.NodeID != "" {
		return o.Mesh.NodeID, nil
	}
	// Check if we are using authentication
	if o.Auth.MTLS != (MTLSOptions{}) {
		// Parse the client certificate for the node ID
		var certDataPEM []byte
		var err error
		if o.Auth.MTLS.CertFile != "" {
			// Parse the certificate file
			certDataPEM, err = os.ReadFile(o.Auth.MTLS.CertFile)
			if err != nil {
				return "", fmt.Errorf("read certificate file: %w", err)
			}
		} else if o.Auth.MTLS.CertData != "" {
			// Base64 decode the certificate data
			certDataPEM, err = base64.StdEncoding.DecodeString(o.Auth.MTLS.CertData)
			if err != nil {
				return "", fmt.Errorf("decode certificate data: %w", err)
			}
		}
		// Decode the PEM block
		block, extra := pem.Decode(certDataPEM)
		if len(extra) > 0 {
			return "", fmt.Errorf("extra data in certificate file")
		}
		// Parse the certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("parse certificate: %w", err)
		}
		// Return the subject common name
		return cert.Subject.CommonName, nil
	}
	if o.Auth.Basic != (BasicAuthOptions{}) {
		// Parse the username for the node ID
		return o.Auth.Basic.Username, nil
	}
	if o.Auth.LDAP != (LDAPAuthOptions{}) {
		// Parse the username for the node ID
		return o.Auth.LDAP.Username, nil
	}
	// If we got this far, set our nodeID so we don't accidentally
	// generate a new one every time.
	o.Mesh.NodeID = DefaultNodeID
	return DefaultNodeID, nil
}
