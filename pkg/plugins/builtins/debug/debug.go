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

// Package debug implements a plugin that exposes an HTTP server for debugging
// purposes.
package debug

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"strings"
	"sync"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/pflag"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/plugins/plugindb"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/version"
)

// Plugin is the debug plugin.
type Plugin struct {
	v1.UnimplementedPluginServer
	v1.UnimplementedStorageQuerierPluginServer

	data    storage.MeshStorage
	datamux sync.Mutex
	closec  chan struct{}
	servec  chan struct{}
}

// Config are the options for the debug plugin.
type Config struct {
	// ListenAddress is the address to listen on. Defaults to "localhost:6060".
	ListenAddress string `mapstructure:"listen-address" koanf:"listen-address"`
	// PathPrefix is the path prefix to use for the debug server.
	// Defaults to "/debug".
	PathPrefix string `mapstructure:"path-prefix" koanf:"path-prefix"`
	// DisablePProf disables pprof.
	DisablePProf bool `mapstructure:"disable-pprof" koanf:"disable-pprof"`
	// PProfProfiles is the list of profiles to enable for pprof.
	// An empty list enables all profiles. Each will be available at
	// /<path-prefix>/pprof/<profile>.
	PprofProfiles string `mapstructure:"pprof-profiles" koanf:"pprof-profiles"`
	// EnableDBQuerier enables the database querier.
	EnableDBQuerier bool `mapstructure:"enable-db-querier" koanf:"enable-db-querier"`
}

// DefaultOptions returns the default options for the plugin.
func (c *Config) DefaultOptions() *Config {
	return &Config{
		ListenAddress: "localhost:6060",
		PathPrefix:    "/debug",
	}
}

func (c *Config) AsMapStructure() map[string]any {
	return map[string]any{
		"listen-address":    c.ListenAddress,
		"path-prefix":       c.PathPrefix,
		"disable-pprof":     c.DisablePProf,
		"pprof-profiles":    c.PprofProfiles,
		"enable-db-querier": c.EnableDBQuerier,
	}
}

func (c *Config) SetMapStructure(in map[string]any) {
	_ = mapstructure.Decode(in, c)
}

// BindFlags binds the debug plugin flags.
func (o *Config) BindFlags(prefix string, fs *pflag.FlagSet) {
	fs.StringVar(&o.ListenAddress, prefix+"listen-address", "localhost:6060", "Address to lissten on")
	fs.StringVar(&o.PathPrefix, prefix+"path-prefix", "/debug", "Path prefix to use for the debug server")
	fs.BoolVar(&o.DisablePProf, prefix+"disable-pprof", o.DisablePProf, "Disable pprof")
	fs.StringVar(&o.PprofProfiles, prefix+"pprof-profiles", "", "Pprof profiles to enable (default: all)")
	fs.BoolVar(&o.EnableDBQuerier, prefix+"enable-db-querier", o.EnableDBQuerier, "Enable database querier")
}

// NewDefaultOptions returns the default options for the debug plugin.
func NewDefaultOptions() Config {
	return Config{
		ListenAddress: "localhost:6060",
		PathPrefix:    "/debug",
	}
}

// GetInfo returns the plugin info.
func (p *Plugin) GetInfo(context.Context, *emptypb.Empty) (*v1.PluginInfo, error) {
	return &v1.PluginInfo{
		Name:        "debug",
		Version:     version.Version,
		Description: "Debug server plugin",
		Capabilities: []v1.PluginInfo_PluginCapability{
			v1.PluginInfo_STORAGE_QUERIER,
		},
	}, nil
}

// Configure configures the plugin.
func (p *Plugin) Configure(ctx context.Context, req *v1.PluginConfiguration) (*emptypb.Empty, error) {
	p.closec = make(chan struct{})
	p.servec = make(chan struct{})
	opts := NewDefaultOptions()
	cfg := req.GetConfig().AsMap()
	if len(cfg) > 0 {
		err := mapstructure.Decode(cfg, &opts)
		if err != nil {
			return nil, fmt.Errorf("failed to decode configuration: %w", err)
		}
	}
	if opts.DisablePProf && !opts.EnableDBQuerier {
		return nil, fmt.Errorf("both pprof and db querier are disabled")
	}
	go p.serve(opts)
	return &emptypb.Empty{}, nil
}

// InjectQuerier injects the querier.
func (p *Plugin) InjectQuerier(srv v1.StorageQuerierPlugin_InjectQuerierServer) error {
	p.datamux.Lock()
	p.data = plugindb.Open(srv)
	p.datamux.Unlock()
	select {
	case <-p.closec:
		return nil
	case <-srv.Context().Done():
		return srv.Context().Err()
	}
}

// Close closes the plugin.
func (p *Plugin) Close(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	p.datamux.Lock()
	defer p.datamux.Unlock()
	close(p.closec)
	<-p.servec
	if p.data != nil {
		return &emptypb.Empty{}, p.data.Close()
	}
	return &emptypb.Empty{}, nil
}

func (p *Plugin) serve(opts Config) {
	defer close(p.servec)
	log := slog.Default().With("plugin", "debug")
	mux := http.NewServeMux()
	pathPrefix := strings.TrimSuffix(opts.PathPrefix, "/")
	if !opts.DisablePProf {
		pprofProfiles := opts.PprofProfiles
		profiles := strings.Split(pprofProfiles, ",")
		if len(profiles) == 0 || (len(profiles) == 1 && profiles[0] == "") {
			profiles = []string{"goroutine", "heap", "allocs", "threadcreate", "block", "mutex"}
		}
		log.Info("Enabling pprof", "profiles", profiles)
		for _, profile := range profiles {
			mux.Handle(fmt.Sprintf("%s/pprof/%s", pathPrefix, profile), pprof.Handler(profile))
		}
	}
	if opts.EnableDBQuerier {
		log.Info("Enabling database querier")
		mux.HandleFunc(fmt.Sprintf("%s/db/list", pathPrefix), p.handleDBList)
		mux.HandleFunc(fmt.Sprintf("%s/db/get", pathPrefix), p.handleDBGet)
		mux.HandleFunc(fmt.Sprintf("%s/db/iter-prefix", pathPrefix), p.handleDBIterPrefix)
	}
	server := &http.Server{
		Addr:    opts.ListenAddress,
		Handler: logRequest(mux),
		BaseContext: func(_ net.Listener) context.Context {
			return context.WithLogger(context.Background(), log)
		},
	}
	go func() {
		log.Info("Starting debug server", "listen-address", opts.ListenAddress)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("Error running debug server", "error", err.Error())
		}
	}()
	<-p.closec
	log.Info("Shutting down debug server")
	if err := server.Shutdown(context.Background()); err != nil {
		log.Error("Error closing debug server", "error", err.Error())
	}
}

func (p *Plugin) handleDBList(w http.ResponseWriter, r *http.Request) {
	p.datamux.Lock()
	defer p.datamux.Unlock()
	defer r.Body.Close()
	if p.data == nil {
		http.Error(w, "plugin not configured", http.StatusInternalServerError)
		return
	}
	log := context.LoggerFrom(r.Context())
	prefix := r.URL.Query().Get("q")
	// We are okay with empty prefix, will return all keys
	log.Info("Listing keys for prefix from database", "prefix", prefix)
	resp, err := p.data.ListKeys(r.Context(), []byte(prefix))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Debug("got keys", "resp", resp)
	fmt.Fprint(w, string(bytes.Join(resp, []byte("\n"))))
}

func (p *Plugin) handleDBGet(w http.ResponseWriter, r *http.Request) {
	p.datamux.Lock()
	defer p.datamux.Unlock()
	defer r.Body.Close()
	if p.data == nil {
		http.Error(w, "plugin not configured", http.StatusInternalServerError)
		return
	}
	log := context.LoggerFrom(r.Context())
	key := r.URL.Query().Get("q")
	if key == "" {
		log.Error("Missing key parameter in request")
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}
	log.Info("Getting key from database", "key", key)
	resp, err := p.data.GetValue(r.Context(), []byte(key))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp = bytes.TrimSpace(resp)
	log.Debug("Got key", "key", key, "resp", string(resp))
	fmt.Fprint(w, string(resp))
}

func (p *Plugin) handleDBIterPrefix(w http.ResponseWriter, r *http.Request) {
	p.datamux.Lock()
	defer p.datamux.Unlock()
	defer r.Body.Close()
	if p.data == nil {
		http.Error(w, "plugin not configured", http.StatusInternalServerError)
		return
	}
	// TODO: may be pointless to implement this
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func logRequest(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log := context.LoggerFrom(r.Context())
		log.Info("Debug Request", "method", r.Method, "url", r.URL.String())
		next.ServeHTTP(w, r)
	}
}
