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
	"flag"
)

// Options are the options for the store.
type Options struct {
	// Mesh are options for participating in an existing mesh.
	Mesh *MeshOptions `json:"join,omitempty" yaml:"join,omitempty" toml:"join,omitempty"`
	// Bootstrap are options for bootstrapping the store.
	Bootstrap *BootstrapOptions `json:"bootstrap,omitempty" yaml:"bootstrap,omitempty" toml:"bootstrap,omitempty"`
	// Raft are options for the raft store.
	Raft *RaftOptions `json:"raft,omitempty" yaml:"raft,omitempty" toml:"raft,omitempty"`
	// TLS are options for TLS.
	TLS *TLSOptions `json:"tls,omitempty" yaml:"tls,omitempty" toml:"tls,omitempty"`
	// WireGuard are options for WireGuard.
	WireGuard *WireGuardOptions `json:"wireguard,omitempty" yaml:"wireguard,omitempty" toml:"wireguard,omitempty"`
}

// NewOptions returns new options with sensible defaults.
func NewOptions() *Options {
	return &Options{
		Bootstrap: NewBootstrapOptions(),
		Mesh:      NewMeshOptions(),
		Raft:      NewRaftOptions(),
		TLS:       NewTLSOptions(),
		WireGuard: NewWireGuardOptions(),
	}
}

// BindFlags binds the options to the flags.
func (o *Options) BindFlags(fl *flag.FlagSet) {
	o.Mesh.BindFlags(fl)
	o.Bootstrap.BindFlags(fl)
	o.Raft.BindFlags(fl)
	o.TLS.BindFlags(fl)
	o.WireGuard.BindFlags(fl)
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
