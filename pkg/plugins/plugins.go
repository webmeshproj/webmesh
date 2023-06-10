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
	"flag"
	"fmt"
	"net"
	"strings"

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/webmeshproj/node/pkg/context"
	"github.com/webmeshproj/node/pkg/plugins/mtls"
)

var (
	// BuiltIns are the built-in plugins.
	BuiltIns = map[string]v1.PluginClient{
		"mtls": inProcessClient(&mtls.Plugin{}),
	}
)

// Manager is the interface for managing plugins.
type Manager interface {
	// AuthPlugin returns the configured auth plugin, if any.
	AuthPlugin() v1.PluginClient
	// AuthUnaryInterceptor returns a unary interceptor for the configured auth plugin, if any.
	AuthUnaryInterceptor() grpc.UnaryServerInterceptor
	// AuthStreamInterceptor returns a stream interceptor for the configured auth plugin, if any.
	AuthStreamInterceptor() grpc.StreamServerInterceptor
}

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

// New creates a new plugin manager.
func New(ctx context.Context, opts *Options) (Manager, error) {
	var auth v1.PluginClient
	for name, cfg := range opts.Plugins {
		if builtIn, ok := BuiltIns[name]; ok {
			caps, err := builtIn.GetInfo(ctx, &emptypb.Empty{})
			if err != nil {
				return nil, fmt.Errorf("get plugin info: %w", err)
			}
			for _, cap := range caps.Capabilities {
				if cap == v1.PluginCapability_PLUGIN_CAPABILITY_AUTH {
					auth = builtIn
				}
			}
			pcfg, err := structpb.NewStruct(cfg.Config)
			if err != nil {
				return nil, fmt.Errorf("convert config: %w", err)
			}
			_, err = builtIn.Configure(ctx, &v1.PluginConfiguration{
				Config: pcfg,
			})
			if err != nil {
				return nil, fmt.Errorf("configure plugin: %w", err)
			}
			continue
		}
	}
	return &manager{
		auth: auth,
	}, nil
}

type manager struct {
	auth v1.PluginClient
}

func (m *manager) AuthPlugin() v1.PluginClient {
	return m.auth
}

func (m *manager) AuthUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if m.auth == nil {
			return handler(ctx, req)
		}
		authReq := m.newAuthRequest(ctx)
		resp, err := m.auth.Authenticate(ctx, authReq)
		if err != nil {
			return nil, fmt.Errorf("authenticate: %w", err)
		}
		ctx = context.WithAuthenticatedCaller(ctx, resp.GetId())
		return handler(ctx, req)
	}
}

func (m *manager) AuthStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if m.auth == nil {
			return handler(srv, ss)
		}
		req := m.newAuthRequest(ss.Context())
		resp, err := m.auth.Authenticate(ss.Context(), req)
		if err != nil {
			return fmt.Errorf("authenticate: %w", err)
		}
		ctx := context.WithAuthenticatedCaller(ss.Context(), resp.GetId())
		return handler(srv, &authenticatedServerStream{ss, ctx})
	}
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

// Serve serves a plugin.
func Serve(ctx context.Context, plugin v1.PluginServer) error {
	port := flag.Int("port", 0, "port to serve on")
	flag.Parse()
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		return err
	}
	defer ln.Close()
	s := grpc.NewServer()
	go func() {
		<-ctx.Done()
		defer ln.Close()
		s.GracefulStop()
	}()
	v1.RegisterPluginServer(s, plugin)
	if err := s.Serve(ln); err != nil {
		return err
	}
	return nil
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

type authenticatedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authenticatedServerStream) Context() context.Context {
	return s.ctx
}
