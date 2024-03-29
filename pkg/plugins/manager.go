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

// Package plugins contains the plugin manager.
package plugins

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/plugins/clients"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/rpcsrv"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

var (
	// ErrUnsupported is returned when a plugin capability is not supported
	// by any of the registered plugins.
	ErrUnsupported = status.Error(codes.Unimplemented, "unsupported plugin capability")
)

// Options are the options for creating a new plugin manager.
type Options struct {
	// Storage is the storage backend to use for plugins.
	Storage storage.Provider
	// Plugins is a map of plugin names to plugin configs.
	Plugins map[string]Plugin
	// Node is the node configuration to pass to each plugin.
	Node NodeConfig
	// DisableDefaultIPAM disables the default IPAM plugin.
	DisableDefaultIPAM bool
	// DefaultIPAMStaticIPv4 is a map of node names to IPv4 addresses.
	DefaultIPAMStaticIPv4 map[string]string
}

// NodeConfig is the configuration of the node to pass to each plugin.
type NodeConfig struct {
	// NodeID is the ID of the node.
	NodeID types.NodeID
	// NetworkIPv4 is the IPv4 network of the mesh
	NetworkIPv4 netip.Prefix
	// NetworkIPv6 is the IPv6 network of the mesh
	NetworkIPv6 netip.Prefix
	// AddressIPv4 is the IPv4 address of the node
	AddressIPv4 netip.Prefix
	// AddressIPv6 is the IPv6 address of the node
	AddressIPv6 netip.Prefix
	// Domain is the domain of the mesh
	Domain string
	// Key is the node's private key
	Key crypto.PrivateKey
}

// Plugin represents a plugin client and its configuration.
type Plugin struct {
	// Client is the plugin client.
	Client clients.PluginClient
	// Config is the plugin configuration.
	Config map[string]any

	// capabilities discovered from the plugin when we started.
	capabilities []v1.PluginInfo_PluginCapability
	// name is the name returned by the plugin.
	name string
}

// hasCapability returns true if the plugin has the given capability.
func (p *Plugin) hasCapability(cap v1.PluginInfo_PluginCapability) bool {
	for _, c := range p.capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

// Manager is the interface for managing plugins.
type Manager interface {
	// Get returns the plugin with the given name.
	Get(name string) (clients.PluginClient, bool)
	// HasAuth returns true if the manager has an auth plugin.
	HasAuth() bool
	// HasWatchers returns true if the manager has any watch plugins.
	HasWatchers() bool
	// AuthUnaryInterceptor returns a unary interceptor for the configured auth plugin.
	// If no plugin is configured, the returned function is a pass-through.
	AuthUnaryInterceptor() grpc.UnaryServerInterceptor
	// AuthStreamInterceptor returns a stream interceptor for the configured auth plugin.
	// If no plugin is configured, the returned function is a pass-through.
	AuthStreamInterceptor() grpc.StreamServerInterceptor
	// AllocateIP calls the configured IPAM plugin to allocate an IP address for the given request.
	// If no IPAM plugin is configured, ErrUnsupported is returned.
	AllocateIP(ctx context.Context, req *v1.AllocateIPRequest) (netip.Prefix, error)
	// ReleaseIP calls the configured IPAM plugin to release an IP address for the given request.
	// If no IPAM plugin is configured, ErrUnsupported is returned.
	ReleaseIP(ctx context.Context, req *v1.ReleaseIPRequest) error
	// Emit emits an event to all watch plugins.
	Emit(ctx context.Context, ev *v1.Event) error
	// Close closes all plugins.
	Close() error
}

// NewManager creates a new plugin manager.
func NewManager(ctx context.Context, opts Options) (Manager, error) {
	// Create the manager.
	log := context.LoggerFrom(ctx).With("component", "plugin-manager")
	plugins := make(map[string]*Plugin, len(opts.Plugins))
	for n, plugin := range opts.Plugins {
		name := n
		plugins[name] = &plugin
	}
	// Query each plugin for its capabilities.
	for name, plugin := range plugins {
		log.Debug("Querying plugin capabilities", "plugin", name)
		resp, err := plugin.Client.GetInfo(ctx, &emptypb.Empty{})
		if err != nil {
			return nil, fmt.Errorf("get plugin info: %w", err)
		}
		log.Debug("Plugin info", slog.Any("info", resp))
		plugin.capabilities = resp.GetCapabilities()
		plugin.name = resp.GetName()
		// Configure the plugin
		conf, err := structpb.NewStruct(plugin.Config)
		if err != nil {
			return nil, fmt.Errorf("convert plugin config to structpb: %w", err)
		}
		_, err = plugin.Client.Configure(ctx, &v1.PluginConfiguration{
			Config: conf,
			NodeConfig: &v1.NodeConfiguration{
				Id:          opts.Node.NodeID.String(),
				NetworkIPv4: opts.Node.NetworkIPv4.String(),
				NetworkIPv6: opts.Node.NetworkIPv6.String(),
				AddressIPv4: opts.Node.AddressIPv4.String(),
				AddressIPv6: opts.Node.AddressIPv6.String(),
				Domain:      opts.Node.Domain,
				PrivateKey:  opts.Node.Key.Bytes(),
			},
		})
		if err != nil {
			return nil, fmt.Errorf("configure plugin: %w", err)
		}
	}
	handleErr := func(cause error) error {
		// Make sure we close all plugins if we fail to start.
		for _, plugin := range plugins {
			_, err := plugin.Client.Close(context.Background(), &emptypb.Empty{})
			if err != nil {
				// Don't report unimplemented close methods.
				if status.Code(err) != codes.Unimplemented {
					log.Error("close plugin", "plugin", plugin.name, "error", err)
				}
			}
		}
		return cause
	}
	// We only support a single auth and IPv4 mechanism for now. So only
	// track the first ones we see
	var auth *Plugin
	var ipamv4 IPAMPlugin
	for name, plugin := range plugins {
		if plugin.hasCapability(v1.PluginInfo_AUTH) {
			if auth != nil {
				return nil, handleErr(fmt.Errorf("multiple auth plugins found: %s, %s", auth.name, name))
			}
			auth = plugin
		}
		if plugin.hasCapability(v1.PluginInfo_IPAMV4) {
			if ipamv4 != nil {
				return nil, handleErr(fmt.Errorf("extra IPAM plugin found: %s", name))
			}
			ipamv4 = plugin.Client.IPAM()
		}
	}
	// If we didn't find any IPAM plugins, register the default one
	if ipamv4 == nil && !opts.DisableDefaultIPAM {
		ipamv4 = NewBuiltinIPAM(IPAMConfig{
			Storage:    opts.Storage.MeshDB(),
			StaticIPv4: opts.DefaultIPAMStaticIPv4,
		})
	}
	m := &manager{
		storage: opts.Storage,
		plugins: plugins,
		auth:    auth,
		ipamv4:  ipamv4,
		log:     log,
	}
	go m.handleQueries(opts.Storage)
	return m, nil
}

// NewManagerWithDB creates a new plugin manager with a storage provider
// and no plugins configured.
func NewManagerWithDB(db storage.Provider) Manager {
	return &manager{
		storage: db,
		plugins: make(map[string]*Plugin),
	}
}

// IPAMPlugin wraps the interface of the IPAM plugin only exposing the Allocate method.
// This makes for ease of use with the built-in IPAM.
type IPAMPlugin interface {
	Allocate(ctx context.Context, r *v1.AllocateIPRequest, opts ...grpc.CallOption) (*v1.AllocatedIP, error)
	Release(ctx context.Context, r *v1.ReleaseIPRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type manager struct {
	storage storage.Provider
	plugins map[string]*Plugin
	auth    *Plugin
	ipamv4  IPAMPlugin
	log     context.Logger
}

// Get returns the plugin with the given name.
func (m *manager) Get(name string) (clients.PluginClient, bool) {
	p, ok := m.plugins[name]
	return p.Client, ok
}

// HasAuth returns true if the manager has an auth plugin.
func (m *manager) HasAuth() bool {
	return m.auth != nil
}

// HasWatchers returns true if the manager has any watch plugins.
func (m *manager) HasWatchers() bool {
	for _, plugin := range m.plugins {
		if plugin.hasCapability(v1.PluginInfo_WATCH) {
			return true
		}
	}
	return false
}

// AuthUnaryInterceptor returns a unary interceptor for the configured auth plugin.
// If no plugin is configured, the returned function is a no-op.
func (m *manager) AuthUnaryInterceptor() grpc.UnaryServerInterceptor {
	var icep grpc.UnaryServerInterceptor
	if m.auth != nil {
		icep = NewAuthUnaryInterceptor(m.auth.Client.Auth())
	}
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if m.auth == nil {
			return handler(ctx, req)
		}
		return icep(ctx, req, info, handler)
	}
}

// NewAuthUnaryInterceptor returns a unary interceptor for the given auth plugin.
func NewAuthUnaryInterceptor(plugin v1.AuthPluginClient) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		resp, err := plugin.Authenticate(ctx, newAuthRequest(ctx))
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "authenticate: %v", err)
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
	var icep grpc.StreamServerInterceptor
	if m.auth != nil {
		icep = NewAuthStreamInterceptor(m.auth.Client.Auth())
	}
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if m.auth == nil {
			return handler(srv, ss)
		}
		return icep(srv, ss, info, handler)
	}
}

// NewAuthStreamInterceptor returns a stream interceptor for the given auth plugin.
func NewAuthStreamInterceptor(plugin v1.AuthPluginClient) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		resp, err := plugin.Authenticate(ss.Context(), newAuthRequest(ss.Context()))
		if err != nil {
			return status.Errorf(codes.Unauthenticated, "authenticate: %v", err)
		}
		log := context.LoggerFrom(ss.Context()).With("caller", resp.GetId())
		ctx := context.WithAuthenticatedCaller(ss.Context(), resp.GetId())
		ctx = context.WithLogger(ctx, log)
		return handler(srv, &authenticatedServerStream{ss, ctx})
	}
}

// AllocateIP calls the configured IPAM plugin to allocate an IP address for the given request.
// If no IPAM plugin is configured, ErrUnsupported is returned.
func (m *manager) AllocateIP(ctx context.Context, req *v1.AllocateIPRequest) (netip.Prefix, error) {
	var addr netip.Prefix
	var err error
	if m.ipamv4 == nil {
		return addr, ErrUnsupported
	}
	res, err := m.ipamv4.Allocate(ctx, req)
	if err != nil {
		return addr, fmt.Errorf("allocate IPv4: %w", err)
	}
	addr, err = netip.ParsePrefix(res.GetIp())
	if err != nil {
		return addr, fmt.Errorf("parse IPv4 address: %w", err)
	}
	return addr, err
}

// ReleaseIP calls the configured IPAM plugin to release an IP address for the given request.
// If no IPAM plugin is configured, ErrUnsupported is returned.
func (m *manager) ReleaseIP(ctx context.Context, req *v1.ReleaseIPRequest) error {
	if m.ipamv4 == nil {
		return ErrUnsupported
	}
	_, err := m.ipamv4.Release(ctx, req)
	return err
}

// Emit emits an event to all watch plugins.
func (m *manager) Emit(ctx context.Context, ev *v1.Event) error {
	errs := make([]error, 0)
	for _, plugin := range m.plugins {
		if plugin.hasCapability(v1.PluginInfo_WATCH) {
			m.log.Debug("Emitting event", "plugin", plugin.name, "event", ev.String())
			_, err := plugin.Client.Events().Emit(ctx, ev)
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("emit: %w", errors.Join(errs...))
	}
	return nil
}

// Close closes all plugins.
func (m *manager) Close() error {
	errs := make([]error, 0)
	for _, p := range m.plugins {
		_, err := p.Client.Close(context.Background(), &emptypb.Empty{})
		if err != nil {
			// Don't report unimplemented close methods.
			if status.Code(err) != codes.Unimplemented {
				errs = append(errs, err)
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("close: %v", errs)
	}
	return nil
}

// handleQueries handles SQL queries from plugins.
func (m *manager) handleQueries(db storage.Provider) {
	for plugin, client := range m.plugins {
		if !client.hasCapability(v1.PluginInfo_STORAGE_QUERIER) {
			return
		}
		ctx := context.Background()
		m.log.Debug("Starting plugin query stream", "plugin", plugin)
		q, err := client.Client.Storage().InjectQuerier(ctx)
		if err != nil {
			if status.Code(err) == codes.Unimplemented {
				m.log.Debug("plugin does not implement queries", "plugin", plugin)
				return
			}
			m.log.Error("Start query stream", "plugin", plugin, "error", err)
			return
		}
		go m.handleQueryClient(plugin, db, q)
	}
}

// handleQueryClient handles a query client.
func (m *manager) handleQueryClient(plugin string, db storage.Provider, queries v1.StorageQuerierPlugin_InjectQuerierClient) {
	err := rpcsrv.Serve(context.WithLogger(context.Background(), m.log), db, queries)
	if err != nil {
		m.log.Error("Error handling query stream", "plugin", plugin, "error", err)
	}
}

func newAuthRequest(ctx context.Context) *v1.AuthenticationRequest {
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
