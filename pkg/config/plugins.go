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
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/plugins"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins"
	"github.com/webmeshproj/webmesh/pkg/plugins/clients"
)

// PluginOptions are options for configuring plugins
type PluginOptions struct {
	// Configs is a map of plugin names to plugin configurations.
	Configs map[string]PluginConfig `koanf:"configs"`
}

// NewPluginOptions returns a new empty PluginOptions.
func NewPluginOptions() PluginOptions {
	return PluginOptions{}
}

// MTLSEnabled reports whether the mtls plugin is configured.
func (o *PluginOptions) MTLSEnabled() bool {
	if o == nil {
		return false
	}
	_, ok := o.Configs["mtls"]
	return ok
}

// BindFlags binds the flags for the plugin options.
func (o *PluginOptions) BindFlags(prefix string, fs *pflag.FlagSet) {
	seen := map[string]struct{}{}
	if len(os.Args[1:]) > 0 {
		for _, arg := range os.Args[1:] {
			flagPrefix := fmt.Sprintf("--%s", prefix)
			if strings.HasPrefix(arg, flagPrefix) {
				arg = strings.TrimPrefix(arg, flagPrefix)
				split := strings.Split(arg, ".")
				if len(split) < 2 {
					continue
				}
				pluginName := split[0]
				seen[pluginName] = struct{}{}
			}
		}
	}
	if len(seen) == 0 {
		return
	}
	o.Configs = map[string]PluginConfig{}
	builtInConfigs := builtins.NewPluginConfigs()
	for pluginName := range seen {
		conf := PluginConfig{}
		flagPrefix := prefix + pluginName + "."
		if pluginConfig, ok := builtInConfigs[pluginName]; ok {
			pconf := pluginConfig
			pconf.BindFlags(flagPrefix, fs)
			conf.Config = pconf.AsMapStructure()
			conf.builtinConfig = pconf
		} else {
			conf.Config = PluginMapConfig{}
			fs.Var(&conf.Config, flagPrefix+"config", "Configuration for the plugin as comma separated key values.")
			conf.BindFlags(flagPrefix, fs)
		}
		o.Configs[pluginName] = conf
	}
}

// PluginConfig is the configuration for a plugin.
type PluginConfig struct {
	// Exec is the configuration for an executable plugin.
	Exec ExecutablePluginConfig `koanf:"exec,omitempty"`
	// Remote is the configuration for a plugin that connects to an external server.
	Remote RemotePluginConfig `koanf:"remote,omitempty"`
	// Config is the configuration that will be passed to the plugin's Configure method.
	Config PluginMapConfig `koanf:"config,omitempty"`

	builtinConfig builtins.FlagBinder
}

// BindFlags binds the flags for the plugin configuration.
func (o *PluginConfig) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.Var(&o.Config, prefix+"config", "Configuration for the plugin as comma separated key values.")
	o.Exec.BindFlags(prefix, fs)
	o.Remote.BindFlags(prefix, fs)
}

// ExecutablePluginConfig is the configuration for an executable plugin.
type ExecutablePluginConfig struct {
	// Path is the path to an executable for the plugin.
	Path string `kaonf:"path,omitempty"`
}

// BindFlags binds the flags for the executable plugin configuration.
func (o *ExecutablePluginConfig) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.StringVar(&o.Path, prefix+"exec.path", o.Path, "Path to the executable for the plugin.")
}

// RemotePluginConfig is the configuration for a plugin that connects to an external server.
type RemotePluginConfig struct {
	// Server is the address of a server for the plugin.
	Server string `koanf:"server,omitempty"`
	// Insecure is whether to use an insecure connection to the plugin server.
	Insecure bool `koanf:"insecure,omitempty"`
	// TLSCAFile is the path to a CA for verifying certificates.
	TLSCAFile string `koanf:"tls-ca-file,omitempty"`
	// TLSCertFile is the path to a certificate for authenticating to the plugin server.
	TLSCertFile string `koanf:"tls-cert-file,omitempty"`
	// TLSKeyFile is the path to a key for authenticating to the plugin server.
	TLSKeyFile string `koanf:"tls-key-file,omitempty"`
	// TLSSkipVerify is whether to skip verifying the plugin server's certificate.
	TLSSkipVerify bool `koanf:"tls-skip-verify,omitempty"`
}

// BindFlags binds the flags for the remote plugin configuration.
func (o *RemotePluginConfig) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.StringVar(&o.Server, prefix+"remote.server", o.Server, "Address of the server for the plugin.")
	fs.BoolVar(&o.Insecure, prefix+"remote.insecure", o.Insecure, "Whether to use an insecure connection to the plugin server.")
	fs.StringVar(&o.TLSCAFile, prefix+"remote.tls-ca-file", o.TLSCAFile, "Path to a CA for verifying certificates.")
	fs.StringVar(&o.TLSCertFile, prefix+"remote.tls-cert-file", o.TLSCertFile, "Path to a certificate for authenticating to the plugin server.")
	fs.StringVar(&o.TLSKeyFile, prefix+"remote.tls-key-file", o.TLSKeyFile, "Path to a key for authenticating to the plugin server.")
	fs.BoolVar(&o.TLSSkipVerify, prefix+"remote.tls-skip-verify", o.TLSSkipVerify, "Whether to skip verifying the plugin server's certificate.")
}

// NewPluginSet returns a new plugin set for the node configuration. This
// will only work if the PluginOptions have been bound to a parsed flagset.
func (o *PluginOptions) NewPluginSet(ctx context.Context) (map[string]plugins.Plugin, error) {
	if len(o.Configs) == 0 {
		return nil, nil
	}
	pluginSet := map[string]plugins.Plugin{}
	for pluginName, pluginConfig := range o.Configs {
		name := pluginName
		// Create a client for the plugin
		builtinClients := builtins.NewPluginMap()
		var cli clients.PluginClient
		var err error
		if builtin, ok := builtinClients[name]; ok {
			cli = builtin
			// Set any flag arguments back to the config
			pluginConfig.Config = pluginConfig.builtinConfig.AsMapStructure()
		} else if pluginConfig.Exec != (ExecutablePluginConfig{}) {
			cli, err = clients.NewExternalProcessClient(ctx, pluginConfig.Exec.Path)
			if err != nil {
				return nil, fmt.Errorf("failed to load executable plugin: %w", err)
			}
		} else {
			// It's a remote server plugin
			cli, err = clients.NewExternalServerClient(ctx, &clients.ExternalServerConfig{
				Server:        pluginConfig.Remote.Server,
				Insecure:      pluginConfig.Remote.Insecure,
				TLSCAFile:     pluginConfig.Remote.TLSCAFile,
				TLSCertFile:   pluginConfig.Remote.TLSCertFile,
				TLSKeyFile:    pluginConfig.Remote.TLSKeyFile,
				TLSSkipVerify: pluginConfig.Remote.TLSSkipVerify,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to dial remote plugin: %w", err)
			}
		}
		plug := plugins.Plugin{
			Client: cli,
			Config: pluginConfig.Config,
		}
		pluginSet[name] = plug
	}
	return pluginSet, nil
}

// PluginMapConfig implements a pflag.Value and wraps a map[string]any.
type PluginMapConfig map[string]any

func (p PluginMapConfig) String() string {
	if p == nil {
		p = PluginMapConfig{}
	}
	out, _ := json.Marshal(p)
	return string(out)
}

func (p PluginMapConfig) Set(s string) error {
	// We split the string on commas first
	if p == nil {
		p = PluginMapConfig{}
	}
	fields := strings.Split(s, ",")
	for _, field := range fields {
		spl := strings.Split(field, "=")
		if len(spl) != 2 {
			return fmt.Errorf("invalid plugin configuration: %s", field)
		}
		key, val := spl[0], spl[1]
		p[key] = func() any {
			// Try to parse as a bool
			b, err := strconv.ParseBool(val)
			if err == nil {
				return b
			}
			// Try to parse as an integer
			i, err := strconv.Atoi(val)
			if err == nil {
				return i
			}
			return val
		}()
	}
	return nil
}

func (p PluginMapConfig) Type() string {
	return "plugin-config"
}
