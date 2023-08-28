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

package nodecmd

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/webmeshproj/webmesh/pkg/cmd/nodecmd/options"
	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/meshbridge"
	"github.com/webmeshproj/webmesh/pkg/services"
)

// GenMarkdownDoc generates markdown documentation for the node command
func GenMarkdownDoc(title string, weight int, outfile string) error {
	var sb strings.Builder
	// Doc header
	sb.WriteString(fmt.Sprintf(`---
title: %s
weight: %d
---
`, title, weight))
	// Prelude
	prelude := `
Each node can be configured to bootstrap a new cluster or join an existing cluster.
When bootstrapping a new cluster, the node will become the leader of the cluster.
When joining an existing cluster, the node will attempt to join the cluster by contacting the leader.

Optionally, the node can be configured to bootstrap with a set of initial nodes.
When bootstrapping with initial nodes, the nodes will perform an election to determine which node should write the initial network configuration.
If the initial nodes are already part of a cluster, the node will join the cluster by contacting the leader of the cluster.

Configuration is available via command line flags, environment variables, and configuration files.
The configuration is parsed in the following order:

- Environment Variables
- Command Line Flags
- Configuration File

Environment variables match the command line flags where all characters are uppercased and dashes and dots are replaced with underscores.
For example, the command line flag BACKTICKmesh.node-idBACKTICK would be set via the environment variable BACKTICKMESH_NODE_IDBACKTICK.

Configuration files can be in YAML, JSON, or TOML.
The configuration file is specified via the "--config" flag.
The configuration file matches the structure of the command line flags.
For example, the following YAML configuration would be equivalent to the shown command line flag:

FENCEyaml
# config.yaml
mesh:
  node-id: "node-1" # --mesh.node-id="node-1"
FENCE

The below tables show all of the available configuration options and their default values.

{{< toc >}}

FENCE
General Flags

  --config         Load flags from the given configuration file
  --print-config   Print the configuration and exit

  --help       Show this help message
  --version    Show version information and exit
FENCE

`
	prelude = strings.ReplaceAll(prelude, "BACKTICK", "`")
	prelude = strings.ReplaceAll(prelude, "FENCE", "```")
	sb.WriteString(prelude)
	appendFlagSection("Global Configurations", "global", &sb)
	appendFlagSection("Mesh Configurations", "mesh", &sb)
	appendFlagSection("Auth Configurations", "auth", &sb)
	// Auth disclaimer about needing more flags
	sb.WriteString("_TODO: Generic flags need to be provided for external plugin auth providers_\n\n")
	appendFlagSection("Bootstrap Configurations", "bootstrap", &sb)
	appendFlagSection("Raft Configurations", "raft", &sb)
	appendFlagSection("TLS Configurations", "tls", &sb)
	appendFlagSection("WireGuard Configurations", "wireguard", &sb)
	appendFlagSection("Discovery Configurations", "discovery", &sb)
	appendFlagSection("Services Configurations", "services", &sb)
	appendFlagSection("Plugin Configurations", "plugins", &sb)
	return os.WriteFile(outfile, []byte(sb.String()), 0644)
}

// GenBridgeMarkdownDoc generates the markdown documentation for the bridge commands.
func GenBridgeMarkdownDoc(title string, weight int, outfile string) error {
	var sb strings.Builder
	config := options.NewOptions().BindFlags(flagset)
	config.Bridge.Meshes = make(map[string]*meshbridge.MeshOptions)
	config.Bridge.Meshes["<mesh-id>"] = &meshbridge.MeshOptions{
		Mesh:     mesh.NewDefaultOptions(),
		Services: services.NewOptions(0),
	}
	config.Bridge.Meshes["<mesh-id>"].BindFlags(flagset, "<iface-name>", "bridge", "<mesh-id>")
	// Doc header
	sb.WriteString(fmt.Sprintf(`---
title: %s
weight: %d
---
`, title, weight))

	// Prelude
	prelude := `
In bridge mode, the options are identical to the node command, except you define multiple mesh connections.
Each mesh connection is defined by a unique mesh ID and it's connection and service options.
One notable exception is that MeshDNS servers defined on the mesh level are ignored in favor of the global one.

In contrast to a regular node, environment variables are not supported.
They will take precedence over the defaults in some cases, but not all.
Global flags are supported, but do not override TLS and some WireGuard configurations.
`
	sb.WriteString(prelude)
	appendFlagSection("Global Configurations", "global", &sb)
	appendFlagSectionNoEnv("Mesh DNS Server Configurations", "bridge.services.meshdns", &sb)
	appendFlagSectionNoEnv("Mesh DNS Client Configurations", "bridge.use-meshdns", &sb)
	appendFlagSectionNoEnv("Mesh Configurations", "bridge.<mesh-id>.mesh", &sb)
	appendFlagSectionNoEnv("Auth Configurations", "bridge.<mesh-id>.auth", &sb)
	// Auth disclaimer about needing more flags
	sb.WriteString("_TODO: Generic flags need to be provided for external plugin auth providers_\n\n")
	appendFlagSectionNoEnv("Bootstrap Configurations", "bridge.<mesh-id>.bootstrap", &sb)
	appendFlagSectionNoEnv("Raft Configurations", "bridge.<mesh-id>.raft", &sb)
	appendFlagSectionNoEnv("TLS Configurations", "bridge.<mesh-id>.tls", &sb)
	appendFlagSectionNoEnv("WireGuard Configurations", "bridge.<mesh-id>.wireguard", &sb)
	appendFlagSectionNoEnv("Discovery Configurations", "bridge.<mesh-id>.discovery", &sb)
	appendFlagSectionNoEnv("Services Configurations", "bridge.<mesh-id>.services", &sb, "meshdns")
	appendFlagSectionNoEnv("Plugin Configurations", "bridge.<mesh-id>.plugins", &sb)
	return os.WriteFile(outfile, []byte(sb.String()), 0644)
}

func appendFlagSection(title string, flagPrefix string, sb *strings.Builder) {
	if title != "" {
		sb.WriteString(fmt.Sprintf("## %s\n\n", title))
	}
	sb.WriteString("| CLI Flag | Env Var | Config File | Default | Description |\n")
	sb.WriteString("| -------- | ------- | ----------- | ------- | ----------- |\n")
	flagset.VisitAll(func(f *flag.Flag) {
		if !strings.HasPrefix(f.Name, flagPrefix) {
			return
		}
		usage := strings.ReplaceAll(f.Usage, "\n", " ")
		re := regexp.MustCompile("<(.*?)>")
		usage = re.ReplaceAllString(usage, "`<$1>`")
		sb.WriteString(fmt.Sprintf("| `--%s` | `%s` | `%s` | %s | %s |\n",
			f.Name,
			strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(f.Name, "-", "_"), ".", "_")),
			f.Name,
			func() string {
				if f.DefValue == "" {
					return ""
				}
				return fmt.Sprintf("`%s`", f.DefValue)
			}(),
			usage,
		))
	})
	sb.WriteString("\n")
}

func appendFlagSectionNoEnv(title string, flagPrefix string, sb *strings.Builder, skipStr ...string) {
	sb.WriteString(fmt.Sprintf("## %s\n\n", title))
	sb.WriteString("| CLI Flag | Config File | Default | Description |\n")
	sb.WriteString("| -------- | ----------- | ------- | ----------- |\n")
	flagset.VisitAll(func(f *flag.Flag) {
		for _, str := range skipStr {
			if strings.Contains(f.Name, str) {
				return
			}
		}
		if !strings.HasPrefix(f.Name, flagPrefix) {
			return
		}
		usage := strings.ReplaceAll(f.Usage, "\n", " ")
		re := regexp.MustCompile("<(.*?)>")
		usage = re.ReplaceAllString(usage, "`<$1>`")
		sb.WriteString(fmt.Sprintf("| `--%s` | `%s` | %s | %s |\n",
			f.Name,
			f.Name,
			func() string {
				if f.DefValue == "" {
					return ""
				}
				return fmt.Sprintf("`%s`", f.DefValue)
			}(),
			usage,
		))
	})
	sb.WriteString("\n")
}
