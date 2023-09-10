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

package bridgecmd

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/config"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins"
)

// GenMarkdownDoc generates the markdown documentation for the bridge commands.
func GenMarkdownDoc(title string, weight int, outfile string) error {
	var sb strings.Builder
	flagset := pflag.NewFlagSet("webmesh-bridge", pflag.ContinueOnError)
	conf := (&config.Config{}).BindFlags("", flagset)
	conf.Bridge = config.BridgeOptions{
		Meshes: map[string]*config.Config{
			"<mesh-id>": conf,
		},
		MeshDNS:    config.BridgeMeshDNSOptions{},
		UseMeshDNS: false,
	}
	conf.Bridge.Meshes["<mesh-id>"].BindFlags("bridge.<mesh-id>.", flagset)
	pluginConfigs := builtins.NewPluginConfigs()
	for pluginName, pluginConfig := range pluginConfigs {
		pluginConfig.BindFlags(fmt.Sprintf("bridge.<mesh-id>.plugins.%s.", pluginName), flagset)
	}
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
	appendFlagSection(flagset, "Global Configurations", "global", &sb)
	appendFlagSectionNoEnv(flagset, "Mesh DNS Server Configurations", "bridge.meshdns", &sb)
	appendFlagSectionNoEnv(flagset, "Mesh DNS Client Configurations", "bridge.use-meshdns", &sb)
	appendFlagSectionNoEnv(flagset, "Mesh Configurations", "bridge.<mesh-id>.mesh", &sb)
	appendFlagSectionNoEnv(flagset, "Auth Configurations", "bridge.<mesh-id>.auth", &sb)
	// Auth disclaimer about needing more flags
	sb.WriteString("_TODO: Generic flags need to be provided for external plugin auth providers_\n\n")
	appendFlagSectionNoEnv(flagset, "Bootstrap Configurations", "bridge.<mesh-id>.bootstrap", &sb)
	appendFlagSectionNoEnv(flagset, "Raft Configurations", "bridge.<mesh-id>.raft", &sb)
	appendFlagSectionNoEnv(flagset, "TLS Configurations", "bridge.<mesh-id>.tls", &sb)
	appendFlagSectionNoEnv(flagset, "WireGuard Configurations", "bridge.<mesh-id>.wireguard", &sb)
	appendFlagSectionNoEnv(flagset, "Discovery Configurations", "bridge.<mesh-id>.discovery", &sb)
	appendFlagSectionNoEnv(flagset, "Services Configurations", "bridge.<mesh-id>.services", &sb, "meshdns")
	appendFlagSectionNoEnv(flagset, "Plugin Configurations", "bridge.<mesh-id>.plugins", &sb)
	return os.WriteFile(outfile, []byte(sb.String()), 0644)
}

func appendFlagSection(flagset *pflag.FlagSet, title string, flagPrefix string, sb *strings.Builder) {
	if title != "" {
		sb.WriteString(fmt.Sprintf("## %s\n\n", title))
	}
	sb.WriteString("| CLI Flag | Env Var | Config File | Default | Description |\n")
	sb.WriteString("| -------- | ------- | ----------- | ------- | ----------- |\n")
	flagset.VisitAll(func(f *pflag.Flag) {
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

func appendFlagSectionNoEnv(flagset *pflag.FlagSet, title string, flagPrefix string, sb *strings.Builder, skipStr ...string) {
	sb.WriteString(fmt.Sprintf("## %s\n\n", title))
	sb.WriteString("| CLI Flag | Config File | Default | Description |\n")
	sb.WriteString("| -------- | ----------- | ------- | ----------- |\n")
	flagset.VisitAll(func(f *pflag.Flag) {
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
