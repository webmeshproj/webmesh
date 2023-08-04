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

// Package meshbridge contains a wrapper interface for running multiple mesh connections
// in parallel and sharing routes between them.
package meshbridge

import (
	"flag"
	"os"
	"strings"

	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/services"
)

// Options are options for the bridge.
type Options struct {
	// Meshes are the meshes to bridge.
	Meshes map[string]*MeshOptions `json:",inline" yaml:",inline" toml:",inline"`
}

// BindFlags binds the options to the given flagset.
func (o *Options) BindFlags(fs *flag.FlagSet) {
	// Iterate flags to determine which bridge options to bind.
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "--bridge.") {
			parts := strings.Split(arg, ".")
			if len(parts) < 3 {
				continue
			}
			meshID := parts[1]
			if _, ok := o.Meshes[meshID]; !ok {
				o.Meshes[meshID] = &MeshOptions{
					Mesh:     mesh.NewOptions(),
					Services: services.NewOptions(),
				}
			}
		}
	}
	for name, opts := range o.Meshes {
		opts.BindFlags(fs, "bridge", name)
	}
}

// MeshOptions are options for a mesh connection.
type MeshOptions struct {
	// Mesh are the options for the mesh to connect to.
	Mesh *mesh.Options `json:",inline" yaml:",inline" toml:",inline"`
	// Services are the options for services to run and/or advertise.
	Services *services.Options `yaml:"services,omitempty" json:"services,omitempty" toml:"services,omitempty"`
}

// BindFlags binds the options to the given flagset.
func (o *MeshOptions) BindFlags(fs *flag.FlagSet, prefix ...string) {
	o.Mesh.BindFlags(fs, prefix...)
	o.Services.BindFlags(fs, prefix...)
}

// NewOptions returns new options.
func NewOptions() *Options {
	return &Options{
		Meshes: map[string]*MeshOptions{},
	}
}
