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

// Package plugins contains the interface for using plugins to extend the functionality of the node.
package plugins

import (
	"fmt"
	"strings"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/plugins/basicauth"
	"github.com/webmeshproj/node/pkg/plugins/ldap"
	"github.com/webmeshproj/node/pkg/plugins/localstore"
	"github.com/webmeshproj/node/pkg/plugins/mtls"
)

var (
	// BuiltIns are the built-in plugins.
	BuiltIns = map[string]v1.PluginClient{
		"mtls":       inProcessClient(&mtls.Plugin{}),
		"basic-auth": inProcessClient(&basicauth.Plugin{}),
		"ldap":       inProcessClient(&ldap.Plugin{}),
		"localstore": inProcessClient(&localstore.Plugin{}),
	}
)

// Manager is the interface for managing plugins.
type Manager interface {
	// Get returns the plugin with the given name.
	Get(name string) (v1.PluginClient, bool)
	// HasAuth returns true if the manager has an auth plugin.
	HasAuth() bool
	// AuthUnaryInterceptor returns a unary interceptor for the configured auth plugin.
	// If no plugin is configured, the returned function is a pass-through.
	AuthUnaryInterceptor() grpc.UnaryServerInterceptor
	// AuthStreamInterceptor returns a stream interceptor for the configured auth plugin.
	// If no plugin is configured, the returned function is a pass-through.
	AuthStreamInterceptor() grpc.StreamServerInterceptor
	// ApplyRaftLog applies a raft log entry to all storage plugins. Responses are still returned
	// even if an error occurs.
	ApplyRaftLog(ctx context.Context, entry *v1.RaftLogEntry) ([]*v1.RaftApplyResponse, error)
	// Emit emits an event to all watch plugins.
	Emit(ctx context.Context, ev *v1.Event) error
}

// New creates a new plugin manager.
func New(ctx context.Context, opts *Options) (Manager, error) {
	var auth v1.PluginClient
	registered := make(map[string]v1.PluginClient)
	stores := make([]v1.PluginClient, 0)
	emitters := make([]v1.PluginClient, 0)
	log := slog.Default()
	for name, cfg := range opts.Plugins {
		log.Info("loading plugin", "name", name)
		log.Debug("plugin configuration", "config", cfg)
		// Load the plugin.
		var plugin v1.PluginClient
		if builtIn, ok := BuiltIns[name]; ok {
			plugin = builtIn
		} else {
			if cfg.Path == "" && cfg.Server == "" {
				return nil, fmt.Errorf("plugin %q: path or server must be specified", name)
			}
			if cfg.Path != "" && cfg.Server != "" {
				return nil, fmt.Errorf("plugin %q: path and server cannot both be specified", name)
			}
			var err error
			if cfg.Path != "" {
				plugin, err = newExternalProcess(ctx, cfg.Path)
			} else {
				plugin, err = newExternalServer(ctx, cfg.Server)
			}
			if err != nil {
				return nil, fmt.Errorf("plugin %q: %w", name, err)
			}
		}
		// Configure the plugin.
		info, err := plugin.GetInfo(ctx, &emptypb.Empty{})
		if err != nil {
			return nil, fmt.Errorf("get plugin info: %w", err)
		}
		for _, cap := range info.Capabilities {
			if cap == v1.PluginCapability_PLUGIN_CAPABILITY_AUTH {
				auth = plugin
			}
			if cap == v1.PluginCapability_PLUGIN_CAPABILITY_STORE {
				stores = append(stores, plugin)
			}
			if cap == v1.PluginCapability_PLUGIN_CAPABILITY_WATCH {
				emitters = append(emitters, plugin)
			}
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
		registered[info.Name] = plugin
	}
	return &manager{
		auth:     auth,
		stores:   stores,
		emitters: emitters,
		plugins:  registered,
		log:      slog.Default().With("component", "plugin-manager"),
	}, nil
}

type manager struct {
	auth     v1.PluginClient
	stores   []v1.PluginClient
	emitters []v1.PluginClient
	plugins  map[string]v1.PluginClient
	log      *slog.Logger
}

// Get returns the plugin with the given name.
func (m *manager) Get(name string) (v1.PluginClient, bool) {
	p, ok := m.plugins[name]
	return p, ok
}

// HasAuth returns true if the manager has an auth plugin.
func (m *manager) HasAuth() bool {
	return m.auth != nil
}

// AuthUnaryInterceptor returns a unary interceptor for the configured auth plugin.
// If no plugin is configured, the returned function is a no-op.
func (m *manager) AuthUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if m.auth == nil {
			return handler(ctx, req)
		}
		resp, err := m.auth.Authenticate(ctx, m.newAuthRequest(ctx))
		if err != nil {
			return nil, fmt.Errorf("authenticate: %w", err)
		}
		log := context.LoggerFrom(ctx).With("caller", resp.GetId())
		ctx = context.WithAuthenticatedCaller(ctx, resp.GetId())
		ctx = context.WithLogger(ctx, log)
		return handler(ctx, req)
	}
}

// AuthStreamInterceptor returns a stream interceptor for the configured auth plugin.
// If no plugin is configured, the returned function is a no-op.
func (m *manager) AuthStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if m.auth == nil {
			return handler(srv, ss)
		}
		resp, err := m.auth.Authenticate(ss.Context(), m.newAuthRequest(ss.Context()))
		if err != nil {
			return fmt.Errorf("authenticate: %w", err)
		}
		log := context.LoggerFrom(ss.Context()).With("caller", resp.GetId())
		ctx := context.WithAuthenticatedCaller(ss.Context(), resp.GetId())
		ctx = context.WithLogger(ctx, log)
		return handler(srv, &authenticatedServerStream{ss, ctx})
	}
}

// ApplyRaftLog applies a raft log entry to all storage plugins.
func (m *manager) ApplyRaftLog(ctx context.Context, entry *v1.RaftLogEntry) ([]*v1.RaftApplyResponse, error) {
	if len(m.stores) == 0 {
		return nil, nil
	}
	out := make([]*v1.RaftApplyResponse, len(m.stores))
	errs := make([]error, 0)
	for i, store := range m.stores {
		resp, err := store.Store(ctx, entry)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out[i] = resp
	}
	var err error
	if len(errs) > 0 {
		err = fmt.Errorf("apply raft log: %v", errs)
	}
	return out, err
}

// Emit emits an event to all watch plugins.
func (m *manager) Emit(ctx context.Context, ev *v1.Event) error {
	if len(m.emitters) == 0 {
		return nil
	}
	errs := make([]error, 0)
	for _, emitter := range m.emitters {
		_, err := emitter.Emit(ctx, ev)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("emit: %v", errs)
	}
	return nil
}

func (m *manager) newAuthRequest(ctx context.Context) *v1.AuthenticationRequest {
	var req v1.AuthenticationRequest
	if md, ok := context.MetadataFrom(ctx); ok {
		headers := make(map[string]string)
		for k, v := range md {
			headers[k] = strings.Join(v, ", ")
		}
		req.Headers = headers
	}
	if authInfo, ok := context.AuthInfoFrom(ctx); ok {
		if tlsInfo, ok := authInfo.(credentials.TLSInfo); ok {
			for _, cert := range tlsInfo.State.PeerCertificates {
				req.Certificates = append(req.Certificates, cert.Raw)
			}
		}
	}
	return &req
}

type authenticatedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authenticatedServerStream) Context() context.Context {
	return s.ctx
}
