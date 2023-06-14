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
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	_ "github.com/mattn/go-sqlite3"
	"github.com/mitchellh/mapstructure"
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/node/pkg/meshdb/models"
	"github.com/webmeshproj/node/pkg/meshdb/raftlogs"
	"github.com/webmeshproj/node/pkg/meshdb/snapshots"
	"github.com/webmeshproj/node/pkg/version"
)

// Plugin is the localstore plugin.
type Plugin struct {
	v1.UnimplementedPluginServer

	data                          *sql.DB
	mux                           sync.Mutex
	termFile, indexFile           string
	currentTerm, lastAppliedIndex atomic.Uint64
	log                           *slog.Logger
}

// Config is the configuration for the localstore plugin.
type Config struct {
	// DataDir is the path to the directory to store data in.
	DataDir string `mapstructure:"data-dir"`
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
	p.log = slog.Default().With("plugin", "localstore")
	var config Config
	err := mapstructure.Decode(req.Config.AsMap(), &config)
	if err != nil {
		return nil, err
	}
	if config.DataDir == "" {
		return nil, fmt.Errorf("path is required")
	}
	err = os.MkdirAll(config.DataDir, 0755)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(config.DataDir, "webmesh.db?_foreign_keys=on&_case_sensitive_like=on&synchronous=full")
	p.data, err = sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	if err = models.MigrateRaftDB(p.data); err != nil {
		return nil, fmt.Errorf("db migrate: %w", err)
	}
	p.termFile = filepath.Join(config.DataDir, ".current-term")
	p.indexFile = filepath.Join(config.DataDir, ".last-applied-index")
	data, err := os.ReadFile(p.termFile)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	} else if err == nil {
		p.log.Debug("restoring current term", "term", string(data))
		p.currentTerm.Store(binary.BigEndian.Uint64(data))
	}
	data, err = os.ReadFile(p.indexFile)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	} else if err == nil {
		p.log.Debug("restoring last applied index", "index", string(data))
		p.lastAppliedIndex.Store(binary.BigEndian.Uint64(data))
	}
	return &emptypb.Empty{}, nil
}

func (p *Plugin) Store(ctx context.Context, log *v1.StoreLogRequest) (*v1.RaftApplyResponse, error) {
	p.mux.Lock()
	defer p.mux.Unlock()
	defer p.currentTerm.Store(log.GetTerm())
	defer p.lastAppliedIndex.Store(log.GetIndex())
	lastIndex := p.lastAppliedIndex.Load()
	if log.GetIndex() <= lastIndex {
		return &v1.RaftApplyResponse{}, nil
	}
	p.log.Info("storing log", "index", log.GetIndex(), "term", log.GetTerm())
	err := os.WriteFile(p.termFile, []byte(fmt.Sprintf("%d", log.GetTerm())), 0644)
	if err != nil {
		return nil, err
	}
	err = os.WriteFile(p.indexFile, []byte(fmt.Sprintf("%d", log.GetIndex())), 0644)
	if err != nil {
		return nil, err
	}
	return raftlogs.Apply(ctx, p.data, log.GetLog()), nil
}

func (p *Plugin) RestoreSnapshot(ctx context.Context, snapshot *v1.DataSnapshot) (*emptypb.Empty, error) {
	p.mux.Lock()
	defer p.mux.Unlock()
	defer p.currentTerm.Store(snapshot.GetTerm())
	defer p.lastAppliedIndex.Store(snapshot.GetIndex())
	p.log.Info("restoring snapshot", "index", snapshot.GetIndex(), "term", snapshot.GetTerm())
	err := os.WriteFile(p.termFile, []byte(fmt.Sprintf("%d", snapshot.GetTerm())), 0644)
	if err != nil {
		return nil, err
	}
	err = os.WriteFile(p.indexFile, []byte(fmt.Sprintf("%d", snapshot.GetIndex())), 0644)
	if err != nil {
		return nil, err
	}
	snapshotter := snapshots.New(p.data)
	return &emptypb.Empty{}, snapshotter.Restore(ctx, io.NopCloser(bytes.NewReader(snapshot.GetData())))
}
