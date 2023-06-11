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
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/plugins/basicauth"
	"github.com/webmeshproj/node/pkg/plugins/mtls"
)

var (
	// BuiltIns are the built-in plugins.
	BuiltIns = map[string]v1.PluginClient{
		"mtls":       inProcessClient(&mtls.Plugin{}),
		"basic-auth": inProcessClient(&basicauth.Plugin{}),
	}
)

// Manager is the interface for managing plugins.
type Manager interface {
	// Get returns the plugin with the given name.
	Get(name string) (v1.PluginClient, bool)
	// HasAuth returns true if the manager has an auth plugin.
	HasAuth() bool
	// AuthUnaryInterceptor returns a unary interceptor for the configured auth plugin.
	// If no plugin is configured, the returned function is a no-op.
	AuthUnaryInterceptor() grpc.UnaryServerInterceptor
	// AuthStreamInterceptor returns a stream interceptor for the configured auth plugin.
	// If no plugin is configured, the returned function is a no-op.
	AuthStreamInterceptor() grpc.StreamServerInterceptor
	// ApplyRaftLog applies a raft log entry to all storage plugins. Responses are still returned
	// even if an error occurs.
	ApplyRaftLog(ctx context.Context, entry *v1.RaftLogEntry) ([]*v1.RaftApplyResponse, error)
	// Emit emits an event to all watch plugins.
	Emit(ctx context.Context, typ string, event proto.Message) error
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
		plugins:  registered,
		stores:   stores,
		emitters: emitters,
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
		ctx = context.WithAuthenticatedCaller(ctx, resp.GetId())
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
		ctx := context.WithAuthenticatedCaller(ss.Context(), resp.GetId())
		return handler(srv, &authenticatedServerStream{ss, ctx})
	}
}

// ApplyRaftLog applies a raft log entry to all storage plugins.
func (m *manager) ApplyRaftLog(ctx context.Context, entry *v1.RaftLogEntry) ([]*v1.RaftApplyResponse, error) {
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
func (m *manager) Emit(ctx context.Context, typ string, event proto.Message) error {
	ev, err := anypb.New(event)
	if err != nil {
		return fmt.Errorf("new any: %w", err)
	}
	errs := make([]error, 0)
	for _, emitter := range m.emitters {
		_, err = emitter.Emit(ctx, &v1.WatchEvent{
			Type:   typ,
			Object: ev,
		})
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

// inProcessClient creates a plugin client from a plugin server.
func inProcessClient(plugin v1.PluginServer) v1.PluginClient {
	return &inProcessPlugin{plugin}
}

type inProcessPlugin struct {
	server v1.PluginServer
}

// GetInfo returns the information for the plugin.
func (p *inProcessPlugin) GetInfo(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*v1.PluginInfo, error) {
	return p.server.GetInfo(ctx, in)
}

// Configure configures the plugin.
func (p *inProcessPlugin) Configure(ctx context.Context, in *v1.PluginConfiguration, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return p.server.Configure(ctx, in)
}

// Store applies a raft log entry to the store.
func (p *inProcessPlugin) Store(ctx context.Context, in *v1.RaftLogEntry, opts ...grpc.CallOption) (*v1.RaftApplyResponse, error) {
	return p.server.Store(ctx, in)
}

// Authenticate authenticates a request.
func (p *inProcessPlugin) Authenticate(ctx context.Context, in *v1.AuthenticationRequest, opts ...grpc.CallOption) (*v1.AuthenticationResponse, error) {
	return p.server.Authenticate(ctx, in)
}

// Emit emits a watch event.
func (p *inProcessPlugin) Emit(ctx context.Context, in *v1.WatchEvent, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	return p.server.Emit(ctx, in)
}

type externalProcessPlugin struct {
	path string
	cmd  *exec.Cmd
	mux  sync.Mutex
	cli  v1.PluginClient
}

func newExternalProcess(ctx context.Context, path string) (*externalProcessPlugin, error) {
	p := &externalProcessPlugin{path: path}
	return p, p.start(ctx)
}

// GetInfo returns the information for the plugin.
func (p *externalProcessPlugin) GetInfo(ctx context.Context, in *emptypb.Empty, opts ...grpc.CallOption) (*v1.PluginInfo, error) {
	if err := p.checkProcess(ctx); err != nil {
		return nil, err
	}
	return p.cli.GetInfo(ctx, in)
}

// Configure configures the plugin.
func (p *externalProcessPlugin) Configure(ctx context.Context, in *v1.PluginConfiguration, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	if err := p.checkProcess(ctx); err != nil {
		return nil, err
	}
	return p.cli.Configure(ctx, in)
}

// Store applies a raft log entry to the store.
func (p *externalProcessPlugin) Store(ctx context.Context, in *v1.RaftLogEntry, opts ...grpc.CallOption) (*v1.RaftApplyResponse, error) {
	if err := p.checkProcess(ctx); err != nil {
		return nil, err
	}
	return p.cli.Store(ctx, in)
}

// Authenticate authenticates a request.
func (p *externalProcessPlugin) Authenticate(ctx context.Context, in *v1.AuthenticationRequest, opts ...grpc.CallOption) (*v1.AuthenticationResponse, error) {
	if err := p.checkProcess(ctx); err != nil {
		return nil, err
	}
	return p.cli.Authenticate(ctx, in)
}

// Emit emits a watch event.
func (p *externalProcessPlugin) Emit(ctx context.Context, in *v1.WatchEvent, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	if err := p.checkProcess(ctx); err != nil {
		return nil, err
	}
	return p.cli.Emit(ctx, in)
}

// checkProcess checks if the process is running and restarts it if it is not.
func (p *externalProcessPlugin) checkProcess(ctx context.Context) error {
	if p.cmd.ProcessState != nil {
		_, ok := ctx.Deadline()
		if !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, time.Now().Add(5*time.Second))
			defer cancel()
		}
		return p.start(ctx)
	}
	return nil
}

// start starts the plugin server.
func (p *externalProcessPlugin) start(ctx context.Context) error {
	p.mux.Lock()
	defer p.mux.Unlock()
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create pipe: %w", err)
	}
	defer r.Close()
	defer w.Close()
	p.cmd = exec.Command(p.path, "--broadcast-fd", strconv.Itoa(int(w.Fd())))
	err = p.cmd.Start()
	if err != nil {
		return fmt.Errorf("start plugin: %w", err)
	}
	// Wait for the address to be written to the pipe.
	b := bufio.NewReader(r)
	if deadline, ok := ctx.Deadline(); ok {
		err = r.SetReadDeadline(deadline)
		if err != nil {
			return fmt.Errorf("set read deadline: %w", err)
		}
	}
	addr, err := b.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read address: %w", err)
	}
	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	p.cli = v1.NewPluginClient(conn)
	return nil
}

type externalServerPlugin struct{ v1.PluginClient }

func newExternalServer(ctx context.Context, addr string) (*externalServerPlugin, error) {
	// TODO: support TLS
	c, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	return &externalServerPlugin{v1.NewPluginClient(c)}, nil
}

type authenticatedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authenticatedServerStream) Context() context.Context {
	return s.ctx
}
