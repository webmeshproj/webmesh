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
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/cmd/cmdutil"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins"
)

var configPrefixes = []string{
	"global",
	"bootstrap",
	"auth",
	"mesh",
	"storage",
	"services",
	"tls",
	"wireguard",
	"discovery",
	"plugin",
}

// Usage returns a string describing the nodecmd's usage.
func Usage() string {
	// Register the builtin plugins for their usage docs.
	pluginConfigs := builtins.NewPluginConfigs()
	for pluginName, pluginConfig := range pluginConfigs {
		pluginConfig.BindFlags(fmt.Sprintf("plugins.%s.", pluginName), flagset)
	}
	return cmdutil.NewUsageFunc(cmdutil.UsageConfig{
		Name: "webmesh-node",
		Description: `webmesh-node is a node in a webmesh cluster. It can be used to run services and join a network.

Configurations are passed via configuration files, environment variables, and command line flags.
The order of precedence for parsing is:
		
	1. Files
	2. Environment variables
	3. Command line flags
`,
		Prefixes:     configPrefixes,
		Flagset:      flagset,
		SkipPrefixes: []string{"bridge"},
	})()
}

// GenMarkdownDoc returns a string describing the nodecmd's usage in markdown format.
func GenMarkdownDoc(title string, weight int, outfile string) error {
	// Register the builtin plugins for their usage docs.
	pluginConfigs := builtins.NewPluginConfigs()
	for pluginName, pluginConfig := range pluginConfigs {
		pluginConfig.BindFlags(fmt.Sprintf("plugins.%s.", pluginName), flagset)
	}
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

- Configuration Files
- Environment Variables
- Command Line Flags

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
	appendFlagSection("Storage Configurations", "storage", &sb, "storage.raft", "storage.external")
	sb.WriteString("#")
	appendFlagSection("Raft Storage Configurations", "storage.raft", &sb)
	sb.WriteString("#")
	appendFlagSection("External Storage Configurations", "storage.external", &sb)
	appendFlagSection("TLS Configurations", "tls", &sb)
	appendFlagSection("WireGuard Configurations", "wireguard", &sb)
	appendFlagSection("Discovery Configurations", "discovery", &sb)
	appendFlagSection("Services Configurations", "services", &sb)
	appendFlagSection("Plugin Configurations", "plugins", &sb)
	return os.WriteFile(outfile, []byte(sb.String()), 0644)
}

func appendFlagSection(title string, flagPrefix string, sb *strings.Builder, skipPrefix ...string) {
	if title != "" {
		sb.WriteString(fmt.Sprintf("## %s\n\n", title))
	}
	sb.WriteString("| CLI Flag | Env Var | Config File | Default | Description |\n")
	sb.WriteString("| -------- | ------- | ----------- | ------- | ----------- |\n")
	flagset.VisitAll(func(f *pflag.Flag) {
		for _, p := range skipPrefix {
			if strings.HasPrefix(f.Name, p) {
				return
			}
		}
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
				if f.DefValue == "" && f.NoOptDefVal == "" {
					return ""
				}
				if f.DefValue != "" {
					return fmt.Sprintf("`%s`", f.DefValue)
				}
				return fmt.Sprintf("`%s`", f.NoOptDefVal)
			}(),
			usage,
		))
	})
	sb.WriteString("\n")
}
