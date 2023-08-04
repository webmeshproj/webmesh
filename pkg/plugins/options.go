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

package plugins

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	v1 "github.com/webmeshproj/api/v1"
)

// Options are the options for loading plugins.
type Options struct {
	// Plugins is a map of plugin names to plugin configs.
	Plugins map[string]*Config `yaml:",inline" json:",inline" toml:",inline"`
}

// Config is the configuration for a plugin.
type Config struct {
	// Plugin is an inline plugin implementation.
	Plugin v1.PluginServer `yaml:"-" json:"-" toml:"-"`
	// Path is the path to an executable for the plugin.
	Path string `yaml:"path,omitempty" json:"path,omitempty" toml:"path,omitempty"`
	// Server is the address of a server for the plugin.
	Server string `yaml:"server,omitempty" json:"server,omitempty" toml:"server,omitempty"`
	// Insecure is whether to use an insecure connection to the plugin server.
	Insecure bool `yaml:"insecure,omitempty" json:"insecure,omitempty" toml:"insecure,omitempty"`
	// TLSCAFile is the path to a CA for verifying certificates.
	TLSCAFile string `yaml:"tls-ca-file,omitempty" json:"tls-ca-file,omitempty" toml:"tls-ca-file,omitempty"`
	// TLSCertFile is the path to a certificate for authenticating to the plugin server.
	TLSCertFile string `yaml:"tls-cert-file,omitempty" json:"tls-cert-file,omitempty" toml:"tls-cert-file,omitempty"`
	// TLSKeyFile is the path to a key for authenticating to the plugin server.
	TLSKeyFile string `yaml:"tls-key-file,omitempty" json:"tls-key-file,omitempty" toml:"tls-key-file,omitempty"`
	// TLSSkipVerify is whether to skip verifying the plugin server's certificate.
	TLSSkipVerify bool `yaml:"tls-skip-verify,omitempty" json:"tls-skip-verify,omitempty" toml:"tls-skip-verify,omitempty"`
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
func (o *Options) BindFlags(fs *flag.FlagSet, prefix ...string) {
	var p string
	if len(prefix) > 0 {
		p = strings.Join(prefix, ".") + "."
	}

	// Built-in plugins

	fs.Func(p+"plugins.mtls.ca-file", "Enables the mTLS plugin with the path to a CA for verifying certificates", func(s string) error {
		o.Plugins["mtls"] = &Config{
			Config: map[string]any{
				"ca-file": s,
			},
		}
		if s == "" {
			return fmt.Errorf("invalid ca-file value: %s", s)
		}
		_, err := os.Stat(s)
		if err != nil {
			return fmt.Errorf("invalid ca-file value: %s", s)
		}
		return nil
	})
	fs.Func(p+"plugins.basic-auth.htpasswd-file", "Enables the basic auth plugin with the path to a htpasswd file", func(s string) error {
		o.Plugins["basic-auth"] = &Config{
			Config: map[string]any{
				"htpasswd-file": s,
			},
		}
		if s == "" {
			return fmt.Errorf("invalid htpasswd-file value: %s", s)
		}
		_, err := os.Stat(s)
		if err != nil {
			return fmt.Errorf("invalid htpasswd-file value: %s", s)
		}
		return nil
	})
	fs.Func(p+"plugins.ldap.server", "Enables the ldap plugin with the server address", func(s string) error {
		if o.Plugins["ldap"] == nil {
			o.Plugins["ldap"] = &Config{
				Config: map[string]any{},
			}
		}
		if s == "" {
			return fmt.Errorf("invalid server value: %s", s)
		}
		toCheck := strings.TrimPrefix(s, "ldap://")
		toCheck = strings.TrimPrefix(toCheck, "ldaps://")
		_, _, err := net.SplitHostPort(toCheck)
		if err != nil {
			return fmt.Errorf("invalid server value: %s", s)
		}
		o.Plugins["ldap"].Config["server"] = s
		return nil
	})
	fs.Func(p+"plugins.ldap.bind-dn", "Enables the ldap plugin with the bind DN", func(s string) error {
		if o.Plugins["ldap"] == nil {
			o.Plugins["ldap"] = &Config{
				Config: map[string]any{},
			}
		}
		if s == "" {
			return fmt.Errorf("invalid bind-dn value: %s", s)
		}
		o.Plugins["ldap"].Config["bind-dn"] = s
		return nil
	})
	fs.Func(p+"plugins.ldap.bind-password", "Enables the ldap plugin with the bind password", func(s string) error {
		if o.Plugins["ldap"] == nil {
			o.Plugins["ldap"] = &Config{
				Config: map[string]any{},
			}
		}
		if s == "" {
			return fmt.Errorf("invalid bind-password value: %s", s)
		}
		o.Plugins["ldap"].Config["bind-password"] = s
		return nil
	})
	fs.Func(p+"plugins.ldap.ca-file", "Enables the ldap plugin with the path to a CA for verifying certificates", func(s string) error {
		if o.Plugins["ldap"] == nil {
			o.Plugins["ldap"] = &Config{
				Config: map[string]any{},
			}
		}
		if s == "" {
			return fmt.Errorf("invalid ca-file value: %s", s)
		}
		_, err := os.Stat(s)
		if err != nil {
			return fmt.Errorf("invalid ca-file value: %s", s)
		}
		o.Plugins["ldap"].Config["ca-file"] = s
		return nil
	})
	fs.Func(p+"plugins.ldap.user-base-dn", "Enables the ldap plugin with the user base DN", func(s string) error {
		if o.Plugins["ldap"] == nil {
			o.Plugins["ldap"] = &Config{
				Config: map[string]any{},
			}
		}
		if s == "" {
			return fmt.Errorf("invalid user-base-dn value: %s", s)
		}
		o.Plugins["ldap"].Config["user-base-dn"] = s
		return nil
	})
	fs.Func(p+"plugins.ldap.user-id-attribute", "Enables the ldap plugin with the user ID attribute", func(s string) error {
		if o.Plugins["ldap"] == nil {
			o.Plugins["ldap"] = &Config{
				Config: map[string]any{},
			}
		}
		if s == "" {
			return fmt.Errorf("invalid user-id-attribute value: %s", s)
		}
		o.Plugins["ldap"].Config["user-id-attribute"] = s
		return nil
	})
	fs.Func(p+"plugins.ldap.node-id-attribute", "Enables the ldap plugin with the node ID attribute", func(s string) error {
		if o.Plugins["ldap"] == nil {
			o.Plugins["ldap"] = &Config{
				Config: map[string]any{},
			}
		}
		if s == "" {
			return fmt.Errorf("invalid node-id-attribute value: %s", s)
		}
		o.Plugins["ldap"].Config["node-id-attribute"] = s
		return nil
	})
	fs.Func(p+"plugins.ldap.user-status-attribute", "Enables the ldap plugin with the user status attribute", func(s string) error {
		if o.Plugins["ldap"] == nil {
			o.Plugins["ldap"] = &Config{
				Config: map[string]any{},
			}
		}
		if s == "" {
			return fmt.Errorf("invalid user-status-attribute value: %s", s)
		}
		o.Plugins["ldap"].Config["user-status-attribute"] = s
		return nil
	})
	fs.Func(p+"plugins.ldap.user-disabled-value", "Enables the ldap plugin with the user disabled value", func(s string) error {
		if o.Plugins["ldap"] == nil {
			o.Plugins["ldap"] = &Config{
				Config: map[string]any{},
			}
		}
		if s == "" {
			return fmt.Errorf("invalid user-disabled-value value: %s", s)
		}
		o.Plugins["ldap"].Config["user-disabled-value"] = s
		return nil
	})
	fs.Func(p+"plugins.debug.listen-address", "Enables the debug plugin with the listen address", func(s string) error {
		if o.Plugins["debug"] == nil {
			o.Plugins["debug"] = &Config{
				Config: map[string]any{},
			}
		}
		_, _, err := net.SplitHostPort(s)
		if err != nil {
			return fmt.Errorf("invalid listen address: %s", s)
		}
		o.Plugins["debug"].Config["listen-address"] = s
		return nil
	})
	fs.Func(p+"plugins.debug.path-prefix", "Enables the debug plugin with the path prefix", func(s string) error {
		if o.Plugins["debug"] == nil {
			o.Plugins["debug"] = &Config{
				Config: map[string]any{},
			}
		}
		if !strings.HasPrefix(s, "/") {
			return fmt.Errorf("invalid path prefix: %s", s)
		}
		o.Plugins["debug"].Config["path-prefix"] = s
		return nil
	})
	fs.Func(p+"plugins.debug.disable-pprof", "Enables the debug plugin with pprof disabled", func(s string) error {
		if o.Plugins["debug"] == nil {
			o.Plugins["debug"] = &Config{
				Config: map[string]any{},
			}
		}
		var err error
		b := true
		if s != "" {
			b, err = strconv.ParseBool(s)
			if err != nil {
				return fmt.Errorf("invalid disable-pprof value: %s", s)
			}
		}
		o.Plugins["debug"].Config["disable-pprof"] = b
		return nil
	})
	fs.Func(p+"plugins.debug.pprof-profiles", "Enables the debug plugin with the pprof profiles", func(s string) error {
		if o.Plugins["debug"] == nil {
			o.Plugins["debug"] = &Config{
				Config: map[string]any{},
			}
		}
		if s == "" {
			return fmt.Errorf("invalid pprof-profiles value: %s", s)
		}
		o.Plugins["debug"].Config["pprof-profiles"] = strings.Split(s, ",")
		return nil
	})
	fs.Func(p+"plugins.debug.enable-db-querier", "Enables the debug plugin with the database querier enabled", func(s string) error {
		if o.Plugins["debug"] == nil {
			o.Plugins["debug"] = &Config{
				Config: map[string]any{},
			}
		}
		var err error
		b := true
		if s != "" {
			b, err = strconv.ParseBool(s)
			if err != nil {
				return fmt.Errorf("invalid enable-db-querier value: %s", s)
			}
		}
		o.Plugins["debug"].Config["enable-db-querier"] = b
		return nil
	})

	// External Plugins

	fs.Func(p+"plugins.local", `A configuration for a local executable plugin.
Provided in the format of <path=/path/to/executable,config1=val1,config2=val2,...>`, func(s string) error {
		keypairs := strings.Split(s, ",")
		if len(keypairs) < 2 {
			return fmt.Errorf("invalid local plugin configuration: %s", s)
		}
		cfg := Config{
			Config: map[string]any{},
		}
		for _, keypair := range keypairs {
			parts := strings.Split(keypair, "=")
			if len(parts) != 2 {
				return fmt.Errorf("invalid local plugin configuration: %s", s)
			}
			switch parts[0] {
			case "path":
				cfg.Path = parts[1]
			default:
				cfg.Config[parts[0]] = parts[1]
			}
		}
		if cfg.Path == "" {
			return fmt.Errorf("invalid local plugin configuration: %s", s)
		}
		o.Plugins[cfg.Path] = &cfg
		return nil
	})
	fs.Func(p+"plugins.server", `A configuration for a remote server plugin. Configurations are the same as the local plugin,
but with the addition of server configurations in the format of:
<server=rpcserver.com:8443[,insecure=true][,tls-ca-file=ca.crt][,tls-key-file=tls.key][,tls-cert-file=tls.crt]>`, func(s string) error {
		keypairs := strings.Split(s, ",")
		if len(keypairs) < 2 {
			return fmt.Errorf("invalid local plugin configuration: %s", s)
		}
		cfg := Config{
			Config: map[string]any{},
		}
		for _, keypair := range keypairs {
			parts := strings.Split(keypair, "=")
			if len(parts) != 2 {
				return fmt.Errorf("invalid local plugin configuration: %s", s)
			}
			switch parts[0] {
			case "server":
				cfg.Server = parts[1]
			case "insecure":
				b, err := strconv.ParseBool(parts[1])
				if err != nil {
					return fmt.Errorf("invalid local plugin configuration: %s", s)
				}
				cfg.Insecure = b
			case "tls-ca-file":
				cfg.TLSCAFile = parts[1]
			case "tls-key-file":
				cfg.TLSKeyFile = parts[1]
			case "tls-cert-file":
				cfg.TLSCertFile = parts[1]
			case "tls-skip-verify":
				b, err := strconv.ParseBool(parts[1])
				if err != nil {
					return fmt.Errorf("invalid local plugin configuration: %s", s)
				}
				cfg.TLSSkipVerify = b
			default:
				cfg.Config[parts[0]] = parts[1]
			}
		}
		if cfg.Server == "" {
			return fmt.Errorf("invalid local plugin configuration: %s", s)
		}
		o.Plugins[cfg.Server] = &cfg
		return nil
	})
}
