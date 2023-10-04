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

// Package builtins contains the built-in plugin implementations.
package builtins

import (
	"github.com/spf13/pflag"

	"github.com/webmeshproj/webmesh/pkg/plugins/builtins/basicauth"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins/debug"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins/ldap"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins/mtls"
	"github.com/webmeshproj/webmesh/pkg/plugins/clients"
)

// NewPluginMap returns a map of the built-in plugins.
func NewPluginMap() map[string]clients.PluginClient {
	return map[string]clients.PluginClient{
		"mtls":       clients.NewInProcessClient(&mtls.Plugin{}),
		"basic-auth": clients.NewInProcessClient(&basicauth.Plugin{}),
		"ldap":       clients.NewInProcessClient(&ldap.Plugin{}),
		"debug":      clients.NewInProcessClient(&debug.Plugin{}),
	}
}

// IsBuiltIn returns true if the plugin is a built-in plugin.
func IsBuiltIn(pluginName string) bool {
	_, ok := NewPluginMap()[pluginName]
	return ok
}

// FlagBinder is an interface implemented by the built-in plugin
// option sets to bind them to the given flag set.
type FlagBinder interface {
	// BindFlags is called to bind the options to the flagset
	// with the given prefix.
	BindFlags(string, *pflag.FlagSet)
	// AsMapStructure is called to convert the options to a map
	// of string keys and values.
	AsMapStructure() map[string]any
	// SetMapStructure is called to set the options from a map
	// of string keys and values.
	SetMapStructure(map[string]any)
}

// NewPluginConfigs returns a map of the built-in plugin configurations.
func NewPluginConfigs() map[string]FlagBinder {
	return map[string]FlagBinder{
		"mtls":       &mtls.Config{},
		"basic-auth": &basicauth.Config{},
		"ldap":       &ldap.Config{},
		"debug":      &debug.Config{},
	}
}
