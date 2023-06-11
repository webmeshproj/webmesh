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

// Package nodecmd contains the entrypoint for webmesh nodes.
package nodecmd

import (
	"bytes"
	"flag"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/webmeshproj/node/pkg/nodecmd/global"
	"github.com/webmeshproj/node/pkg/plugins"
	"github.com/webmeshproj/node/pkg/services"
	"github.com/webmeshproj/node/pkg/store"
)

// Options are the node options.
type Options struct {
	Mesh     *store.Options    `yaml:",inline" json:",inline" toml:",inline"`
	Global   *global.Options   `yaml:"global,omitempty" json:"global,omitempty" toml:"global,omitempty"`
	Services *services.Options `yaml:"services,omitempty" json:"services,omitempty" toml:"services,omitempty"`
	Plugins  *plugins.Options  `yaml:"plugins,omitempty" json:"plugins,omitempty" toml:"plugins,omitempty"`
}

// NewOptions creates new options.
func NewOptions() *Options {
	return &Options{
		Global:   global.NewOptions(),
		Mesh:     store.NewOptions(),
		Services: services.NewOptions(),
		Plugins:  plugins.NewOptions(),
	}
}

// BindFlags binds the flags. The options are returned
// for convenience.
func (o *Options) BindFlags(fs *flag.FlagSet) *Options {
	o.Global.BindFlags(fs)
	o.Mesh.BindFlags(fs)
	o.Services.BindFlags(fs)
	o.Plugins.BindFlags(fs)
	return o
}

// Marshal returns the marshaled options.
func (o *Options) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	err := o.MarshalTo(&buf)
	if err != nil {
		return nil, fmt.Errorf("marshal options: %w", err)
	}
	return buf.Bytes(), nil
}

func (o *Options) MarshalTo(w io.Writer) error {
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	err := enc.Encode(o)
	if err != nil {
		return fmt.Errorf("marshal options: %w", err)
	}
	return nil
}
