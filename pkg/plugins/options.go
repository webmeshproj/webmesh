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

package plugins

import "flag"

// Options are the options for loading plugins.
type Options struct {
	// Plugins is a map of plugin names to plugin configs.
	Plugins map[string]*Config `yaml:"plugins,omitempty" json:"plugins,omitempty" toml:"plugins,omitempty"`
}

// Config is the configuration for a plugin.
type Config struct {
	// Path is the path to an executable for the plugin.
	Path string `yaml:"path,omitempty" json:"path,omitempty" toml:"path,omitempty"`
	// Server is the address of a server for the plugin.
	Server string `yaml:"server,omitempty" json:"server,omitempty" toml:"server,omitempty"`
	// Config is the configuration for the plugin.
	Config map[string]any `yaml:"config,omitempty" json:"config,omitempty" toml:"config,omitempty"`
}

// NewOptions creates new options.
func NewOptions() *Options {
	return &Options{
		Plugins: map[string]*Config{},
	}
}

// BindFlags binds the plugin flags to the given flag set.
func (o *Options) BindFlags(fs *flag.FlagSet) {
	fs.Func("plugins.mtls.ca-file", "Enables the mTLS plugin with the path to a CA for verifying certificates", func(s string) error {
		o.Plugins["mtls"] = &Config{
			Config: map[string]any{
				"ca-file": s,
			},
		}
		return nil
	})
	fs.Func("plugins.basic-auth.htpasswd-file", "Enables the basic auth plugin with the path to a htpasswd file", func(s string) error {
		o.Plugins["basic-auth"] = &Config{
			Config: map[string]any{
				"htpasswd-file": s,
			},
		}
		return nil
	})
}
