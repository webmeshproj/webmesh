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

// Package localstore provides a plugin for persisting raft logs to a local
// SQLite database.
package localstore

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	"github.com/mitchellh/mapstructure"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/node/pkg/meshdb/models"
	"github.com/webmeshproj/node/pkg/meshdb/raftlogs"
	"github.com/webmeshproj/node/pkg/version"
)

// Plugin is the localstore plugin.
type Plugin struct {
	v1.UnimplementedPluginServer

	data *sql.DB
	mux  sync.Mutex
}

// Config is the configuration for the localstore plugin.
type Config struct {
	// Path is the path to the database file.
	Path string `mapstructure:"path"`
}

func (p *Plugin) GetInfo(context.Context, *emptypb.Empty) (*v1.PluginInfo, error) {
	return &v1.PluginInfo{
		Name:        "localstore",
		Version:     version.Version,
		Description: "Local storage plugin",
		Capabilities: []v1.PluginCapability{
			v1.PluginCapability_PLUGIN_CAPABILITY_STORE,
		},
	}, nil
}

func (p *Plugin) Configure(ctx context.Context, req *v1.PluginConfiguration) (*emptypb.Empty, error) {
	var config Config
	err := mapstructure.Decode(req.Config.AsMap(), &config)
	if err != nil {
		return nil, err
	}
	if config.Path == "" {
		return nil, fmt.Errorf("path is required")
	}
	config.Path += "?_foreign_keys=on&_case_sensitive_like=on&synchronous=full"
	p.data, err = sql.Open("sqlite3", config.Path)
	if err != nil {
		return nil, err
	}
	if err = models.MigrateRaftDB(p.data); err != nil {
		return nil, fmt.Errorf("db migrate: %w", err)
	}
	return &emptypb.Empty{}, nil
}

func (p *Plugin) Store(ctx context.Context, log *v1.RaftLogEntry) (*v1.RaftApplyResponse, error) {
	p.mux.Lock()
	defer p.mux.Unlock()
	return raftlogs.Apply(ctx, p.data, log), nil
}
