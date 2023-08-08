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

// Package plugins contains the interface for using plugins to extend the functionality of the node.
package plugins

import (
	"fmt"
	"log/slog"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/plugins/builtins"
	"github.com/webmeshproj/webmesh/pkg/plugins/clients"
)

var (
	// ErrUnsupported is returned when a plugin capability is not supported
	// by any of the registered plugins.
	ErrUnsupported = status.Error(codes.Unimplemented, "unsupported plugin capability")
)

// NewManager creates a new plugin manager.
func NewManager(ctx context.Context, opts *Options) (Manager, error) {
	builtIns := builtins.NewPluginMap()
	var auth, ipamv4, ipamv6 clients.PluginClient
	allPlugins := make(map[string]clients.PluginClient)
	stores := make([]clients.PluginClient, 0)
	emitters := make([]clients.PluginClient, 0)
	log := context.LoggerFrom(ctx)
	for name, cfg := range opts.Plugins {
		log.Info("loading plugin", "name", name)
		log.Debug("plugin configuration", "config", cfg)
		// Load the plugin.
		plugin, err := newPluginClient(ctx, builtIns, name, cfg)
		if err != nil {
			return nil, fmt.Errorf("load plugin %q: %w", name, err)
		}
		// Get the plugin capabilities.
		info, err := plugin.GetInfo(ctx, &emptypb.Empty{})
		if err != nil {
			return nil, fmt.Errorf("get plugin info: %w", err)
		}
		for _, cap := range info.Capabilities {
			switch cap {
			case v1.PluginCapability_PLUGIN_CAPABILITY_AUTH:
				// TODO: allow multiple auth plugins.
				auth = plugin
			case v1.PluginCapability_PLUGIN_CAPABILITY_IPAMV4:
				ipamv4 = plugin
			case v1.PluginCapability_PLUGIN_CAPABILITY_IPAMV6:
				ipamv6 = plugin
			case v1.PluginCapability_PLUGIN_CAPABILITY_STORE:
				stores = append(stores, plugin)
			case v1.PluginCapability_PLUGIN_CAPABILITY_WATCH:
				emitters = append(emitters, plugin)
			}
		}
		// Configure the plugin.
		if cfg.Config == nil {
			cfg.Config = make(map[string]interface{})
		}
		pcfg, err := structpb.NewStruct(cfg.Config)
		if err != nil {
			return nil, fmt.Errorf("convert config: %w", err)
		}
		_, err = plugin.Configure(ctx, &v1.PluginConfiguration{
			Config: pcfg,
		})
		if err != nil {
			return nil, fmt.Errorf("configure plugin %q: %w", name, err)
		}
		allPlugins[name] = plugin
	}
	// If both IPAM plugins are unconfigured, use the in-process IPAM plugin.
	if ipamv4 == nil && ipamv6 == nil {
		ipam := builtIns["ipam"]
		if _, err := ipam.Configure(ctx, &v1.PluginConfiguration{}); err != nil {
			return nil, fmt.Errorf("configure in-process IPAM plugin: %w", err)
		}
		ipamv4 = ipam
		ipamv6 = ipam
		allPlugins["ipam"] = ipam
	}
	m := &manager{
		auth:     auth,
		ipamv4:   ipamv4,
		ipamv6:   ipamv6,
		stores:   stores,
		emitters: emitters,
		plugins:  allPlugins,
		log:      slog.Default().With("component", "plugin-manager"),
	}
	return m, nil
}

func newPluginClient(ctx context.Context, builtIns map[string]clients.PluginClient, name string, cfg *Config) (clients.PluginClient, error) {
	// Check if the plugin is a built-in.
	if builtIn, ok := builtIns[name]; ok {
		return builtIn, nil
	}
	// Special case of in-lined implementation
	if cfg.Plugin != nil {
		return clients.NewInProcessClient(cfg.Plugin), nil
	}
	// Load the plugin from a local executable or remote server
	if cfg.Path == "" && cfg.Server == "" {
		return nil, fmt.Errorf("plugin %q: path or server must be specified", name)
	}
	if cfg.Path != "" && cfg.Server != "" {
		return nil, fmt.Errorf("plugin %q: path and server cannot both be specified", name)
	}
	if cfg.Path != "" {
		return clients.NewExternalProcessClient(ctx, cfg.Path)
	}
	return clients.NewExternalServerClient(ctx, &clients.ExternalServerConfig{
		Server:        cfg.Server,
		Insecure:      cfg.Insecure,
		TLSCAFile:     cfg.TLSCAFile,
		TLSCertFile:   cfg.TLSCertFile,
		TLSKeyFile:    cfg.TLSKeyFile,
		TLSSkipVerify: cfg.TLSSkipVerify,
	})
}
