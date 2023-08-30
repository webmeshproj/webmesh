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
	"fmt"
	"path/filepath"
	"strings"

	"github.com/knadh/koanf/parsers/json"
	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/providers/rawbytes"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/pflag"
)

// LoadFrom attempts to load this configuration from the given flag set,
// configuration files, and environment variables. If fs is not nil, it
// is assumed the configuration has already been bound to the flag set
// and that the flagset has already been parsed.
// The order of precedence for parsing is:
// 1. Files
// 2. Environment variables
// 3. Flags
func (c *Config) LoadFrom(fs *pflag.FlagSet, confFiles []string) error {
	k := koanf.New(".")
	// Iterate over configuration files first
	for _, c := range confFiles {
		switch filepath.Ext(c) {
		case ".json":
			if err := k.Load(file.Provider(c), json.Parser()); err != nil {
				return fmt.Errorf("error loading json file: %w", err)
			}
		case ".yaml":
			if err := k.Load(file.Provider(c), yaml.Parser()); err != nil {
				return fmt.Errorf("error loading yaml file: %w", err)
			}
		case ".toml":
			if err := k.Load(file.Provider(c), toml.Parser()); err != nil {
				return fmt.Errorf("error loading toml file: %w", err)
			}
		}
	}
	// Load environment variables
	err := k.Load(env.Provider("WEBMESH_", ".", func(s string) string {
		return strings.Replace(strings.ToLower(
			strings.TrimPrefix(s, "WEBMESH_")), "_", ".", -1)
	}), nil)
	if err != nil {
		return fmt.Errorf("error loading environment variables: %w", err)
	}

	// Flags override everything
	err = k.Load(posflag.Provider(fs, ".", k), nil)
	if err != nil {
		return fmt.Errorf("error loading flags: %w", err)
	}

	// Finally unmarsal the configuration
	err = k.Unmarshal("", c)
	if err != nil {
		return fmt.Errorf("error unmarshaling configuration: %w", err)
	}
	return nil
}

// MarshalJSON implements json.Marshaler.
func (c Config) MarshalJSON() ([]byte, error) {
	k := koanf.New(".")
	err := k.Load(structs.Provider(c, "koanf"), nil)
	if err != nil {
		return nil, err
	}
	return k.Marshal(json.Parser())
}

// UnmarshalJSON implements json.Unmarshaler.
func (c *Config) UnmarshalJSON(b []byte) error {
	k := koanf.New(".")
	// Load any existing state
	err := k.Load(structs.Provider(c, "koanf"), nil)
	if err != nil {
		return err
	}
	// Load the JSON data
	err = k.Load(rawbytes.Provider(b), json.Parser())
	if err != nil {
		return err
	}
	return k.Unmarshal("", c)
}

// MarshalYAML implements yaml.Marshaler.
func (c Config) MarshalYAML() ([]byte, error) {
	k := koanf.New(".")
	err := k.Load(structs.Provider(c, "koanf"), nil)
	if err != nil {
		return nil, err
	}
	return k.Marshal(yaml.Parser())
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (c *Config) UnmarshalYAML(b []byte) error {
	k := koanf.New(".")
	// Load any existing state
	err := k.Load(structs.Provider(c, "koanf"), nil)
	if err != nil {
		return err
	}
	// Load the YAML data
	err = k.Load(rawbytes.Provider(b), yaml.Parser())
	if err != nil {
		return err
	}
	return k.Unmarshal("", c)
}

// MarshalTOML implements toml.Marshaler.
func (c Config) MarshalTOML() ([]byte, error) {
	k := koanf.New(".")
	err := k.Load(structs.Provider(c, "koanf"), nil)
	if err != nil {
		return nil, err
	}
	return k.Marshal(toml.Parser())
}

// UnmarshalTOML implements toml.Unmarshaler.
func (c *Config) UnmarshalTOML(b []byte) error {
	k := koanf.New(".")
	// Load any existing state
	err := k.Load(structs.Provider(c, "koanf"), nil)
	if err != nil {
		return err
	}
	// Load the TOML data
	err = k.Load(rawbytes.Provider(b), toml.Parser())
	if err != nil {
		return err
	}
	return k.Unmarshal("", c)
}
