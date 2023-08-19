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

// Package nodecmd contains the entrypoint for webmesh nodes.
package nodecmd

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	"github.com/webmeshproj/webmesh/pkg/cmd/nodecmd/global"
	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/meshbridge"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/version"
)

var (
	config = NewOptions().BindFlags(flagset)
)

// Options are the node options.
type Options struct {
	Global *global.Options `yaml:"global,omitempty" json:"global,omitempty" toml:"global,omitempty" mapstructure:"global,omitempty"`

	Mesh     *mesh.Options       `yaml:",inline" json:",inline" toml:",inline" mapstructure:",squash"`
	Bridge   *meshbridge.Options `yaml:"bridge,omitempty" json:"bridge,omitempty" toml:"bridge,omitempty" mapstructure:"bridge,omitempty"`
	Services *services.Options   `yaml:"services,omitempty" json:"services,omitempty" toml:"services,omitempty" mapstructure:"services,omitempty"`
}

// NewOptions creates new options.
func NewOptions() *Options {
	return &Options{
		Global:   global.NewOptions(),
		Mesh:     mesh.NewDefaultOptions(),
		Services: services.NewOptions(0),
		Bridge:   meshbridge.NewOptions(),
	}
}

// BindFlags binds the flags. The options are returned
// for convenience.
func (o *Options) BindFlags(fs *flag.FlagSet) *Options {
	o.Global.BindFlags(fs)
	o.Mesh.BindFlags(fs, "")
	o.Services.BindFlags(fs)
	o.Bridge.BindFlags(fs)
	return o
}

// DeepCopy returns a deep copy of the options.
func (o *Options) DeepCopy() *Options {
	return &Options{
		Global:   o.Global.DeepCopy(),
		Mesh:     o.Mesh.DeepCopy(),
		Bridge:   o.Bridge.DeepCopy(),
		Services: o.Services.DeepCopy(),
	}
}

// Validate runs all the validation checks.
func (o *Options) Validate() error {
	if len(o.Bridge.Meshes) > 0 {
		return o.Bridge.Validate()
	}
	err := o.Mesh.Validate()
	if err != nil {
		return err
	}
	err = o.Services.Validate()
	if err != nil {
		return err
	}
	return nil
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

func usage() {
	fmt.Fprintf(os.Stderr, "Webmesh Node (Version: %s)\n\n", version.Version)
	fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n", os.Args[0])

	fmt.Fprint(os.Stderr, `
The webmesh node is a single node in a webmesh cluster. It is responsible for
tracking the cluster state, managing network configurations, and providing a 
gRPC API for other nodes to interact with the cluster. The API is also used by
the webmesh CLI to interact with the cluster.

The node can be configured to bootstrap a new cluster or join an existing
cluster. When bootstrapping a new cluster, the node will become the leader of
the cluster. When joining an existing cluster, the node will attempt to join
the cluster by contacting the leader. Optionally, the node can be configured to
bootstrap with a set of initial nodes. When bootstrapping with initial nodes,
the node will become the leader of the cluster if the initial nodes are not
already part of a cluster. If the initial nodes are already part of a cluster,
the node will join the cluster by contacting the leader of the cluster.

Configuration is available via command line flags, environment variables, and
configuration files. The configuration is parsed in the following order:

  - Environment Variables
  - Command Line Flags
  - Configuration File

Environment variables match the command line flags where all characters are
uppercased and dashes and dots are replaced with underscores. For example, the
command line flag "mesh.node-id" would be set via the environment variable 
"MESH_NODE_ID".

Configuration files can be in YAML, JSON, or TOML. The configuration file is
specified via the "--config" flag. The configuration file matches the structure 
of the command line flags. For example, the following YAML configuration would 
be equivalent to the shown command line flag:

  # config.yaml
  mesh:
    node-id: "node-1"  # --mesh.node-id="node-1"

`)

	flagsUsage(flagset, "Global Configurations:", "global")
	flagsUsage(flagset, "Mesh Configurations:", "mesh")
	flagsUsage(flagset, "Authentication Configurations:", "auth")
	flagsUsage(flagset, "Bootstrap Configurations:", "bootstrap")
	flagsUsage(flagset, "Raft Configurations:", "raft")
	flagsUsage(flagset, "TLS Configurations:", "tls")
	flagsUsage(flagset, "WireGuard Configurations:", "wireguard")
	flagsUsage(flagset, "Service Configurations:", "services")
	flagsUsage(flagset, "Plugin Configurations:", "plugins")

	fmt.Fprint(os.Stderr, "General Flags\n\n")
	fmt.Fprint(os.Stderr, "  --config         Load flags from the given configuration file\n")
	fmt.Fprint(os.Stderr, "  --print-config   Print the configuration and exit\n")
	fmt.Fprint(os.Stderr, "\n")
	fmt.Fprint(os.Stderr, "  --help       Show this help message\n")
	fmt.Fprint(os.Stderr, "  --version    Show version information and exit\n")
	fmt.Fprint(os.Stderr, "\n")
}

// FlagsUsage prints the usage of all flags with the given prefix.
func flagsUsage(fs *flag.FlagSet, title, prefix string) {
	t := tabwriter.NewWriter(os.Stderr, 1, 4, 4, ' ', 0)
	defer t.Flush()
	fmt.Fprintf(t, "%s\n\n", title)
	fs.VisitAll(func(f *flag.Flag) {
		if !strings.HasPrefix(f.Name, prefix) {
			return
		}
		usageLines := strings.Split(f.Usage, "\n")
		if len(usageLines) > 1 {
			fmt.Fprintln(t)
		}
		if f.DefValue == "" {
			fmt.Fprintf(t, "\t--%s\t\t%s\n", f.Name, usageLines[0])
		} else {
			fmt.Fprintf(t, "\t--%s\t(default: %s)\t%s\n", f.Name, f.DefValue, usageLines[0])
		}
		if len(usageLines) == 1 {
			return
		}
		for _, line := range usageLines[1:] {
			fmt.Fprintf(t, "\t\t\t%s\n", line)
		}
		fmt.Fprintln(t)
	})
	fmt.Fprintf(t, "\n")
}
