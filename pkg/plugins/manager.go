package plugins

import (
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/hashicorp/raft"
	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/plugins/clients"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// Manager is the interface for managing plugins.
type Manager interface {
	// Get returns the plugin with the given name.
	Get(name string) (v1.PluginClient, bool)
	// ServeStorage handles queries from plugins against the given storage backend.
	ServeStorage(db storage.Storage)
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
	// If the requested version does not have a registered plugin, ErrUnsupported is returned.
	AllocateIP(ctx context.Context, req *v1.AllocateIPRequest) (netip.Prefix, error)
	// ApplyRaftLog applies a raft log entry to all storage plugins. Responses are still returned
	// even if an error occurs.
	ApplyRaftLog(ctx context.Context, entry *v1.StoreLogRequest) ([]*v1.RaftApplyResponse, error)
	// ApplySnapshot applies a snapshot to all storage plugins.
	ApplySnapshot(ctx context.Context, meta *raft.SnapshotMeta, data io.ReadCloser) error
	// Emit emits an event to all watch plugins.
	Emit(ctx context.Context, ev *v1.Event) error
	// Close closes all plugins.
	Close() error
}

type manager struct {
	// db       storage.Storage
	auth     clients.PluginClient
	ipamv4   clients.PluginClient
	ipamv6   clients.PluginClient
	stores   []clients.PluginClient
	emitters []clients.PluginClient
	plugins  map[string]clients.PluginClient
	log      *slog.Logger
}

// Get returns the plugin with the given name.
func (m *manager) Get(name string) (v1.PluginClient, bool) {
	p, ok := m.plugins[name]
	return p, ok
}

// ServeStorage handles queries from plugins against the given storage backend.
func (m *manager) ServeStorage(db storage.Storage) {
	m.handleQueries(db)
}

// HasAuth returns true if the manager has an auth plugin.
func (m *manager) HasAuth() bool {
	return m.auth != nil
}

// HasWatchers returns true if the manager has any watch plugins.
func (m *manager) HasWatchers() bool {
	return len(m.emitters) > 0
}

// AuthUnaryInterceptor returns a unary interceptor for the configured auth plugin.
// If no plugin is configured, the returned function is a no-op.
func (m *manager) AuthUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if m.auth == nil {
			return handler(ctx, req)
		}
		resp, err := m.auth.Auth().Authenticate(ctx, m.newAuthRequest(ctx))
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
	return func(srv interface{}, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if m.auth == nil {
			return handler(srv, ss)
		}
		resp, err := m.auth.Auth().Authenticate(ss.Context(), m.newAuthRequest(ss.Context()))
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
// If the requested version does not have a registered plugin, ErrUnsupported is returned.
func (m *manager) AllocateIP(ctx context.Context, req *v1.AllocateIPRequest) (netip.Prefix, error) {
	var addr netip.Prefix
	var err error
	switch req.GetVersion() {
	case v1.AllocateIPRequest_IP_VERSION_4:
		if m.ipamv4 == nil {
			return addr, ErrUnsupported
		}
		res, err := m.ipamv4.IPAM().Allocate(ctx, req)
		if err != nil {
			return addr, fmt.Errorf("allocate IPv4: %w", err)
		}
		addr, err = netip.ParsePrefix(res.GetIp())
		if err != nil {
			return addr, fmt.Errorf("parse IPv4 address: %w", err)
		}
	case v1.AllocateIPRequest_IP_VERSION_6:
		if m.ipamv6 == nil {
			return addr, ErrUnsupported
		}
		res, err := m.ipamv6.IPAM().Allocate(ctx, req)
		if err != nil {
			return addr, fmt.Errorf("allocate IPv6: %w", err)
		}
		addr, err = netip.ParsePrefix(res.GetIp())
		if err != nil {
			return addr, fmt.Errorf("parse IPv6 address: %w", err)
		}
	default:
		err = fmt.Errorf("unsupported IP version: %v", req.GetVersion())
	}
	return addr, err
}

// ApplyRaftLog applies a raft log entry to all storage plugins.
func (m *manager) ApplyRaftLog(ctx context.Context, entry *v1.StoreLogRequest) ([]*v1.RaftApplyResponse, error) {
	if len(m.stores) == 0 {
		return nil, nil
	}
	out := make([]*v1.RaftApplyResponse, len(m.stores))
	errs := make([]error, 0)
	for i, store := range m.stores {
		resp, err := store.Storage().Store(ctx, entry)
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

// ApplySnapshot applies a snapshot to all storage plugins.
func (m *manager) ApplySnapshot(ctx context.Context, meta *raft.SnapshotMeta, data io.ReadCloser) error {
	if len(m.stores) == 0 {
		return nil
	}
	defer data.Close()
	snapsot, err := io.ReadAll(data)
	if err != nil {
		return fmt.Errorf("read snapshot: %w", err)
	}
	errs := make([]error, 0)
	for _, store := range m.stores {
		_, err := store.Storage().RestoreSnapshot(ctx, &v1.DataSnapshot{
			Term:  meta.Term,
			Index: meta.Index,
			Data:  snapsot,
		})
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("apply snapshot: %v", errs)
	}
	return nil
}

// Emit emits an event to all watch plugins.
func (m *manager) Emit(ctx context.Context, ev *v1.Event) error {
	if len(m.emitters) == 0 {
		return nil
	}
	errs := make([]error, 0)
	for _, emitter := range m.emitters {
		_, err := emitter.Events().Emit(ctx, ev)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("emit: %v", errs)
	}
	return nil
}

// Close closes all plugins.
func (m *manager) Close() error {
	errs := make([]error, 0)
	for _, p := range m.plugins {
		_, err := p.Close(context.Background(), &emptypb.Empty{})
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
func (m *manager) handleQueries(db storage.Storage) {
	for plugin, client := range m.plugins {
		ctx := context.Background()
		q, err := client.InjectQuerier(ctx)
		if err != nil {
			if status.Code(err) == codes.Unimplemented {
				m.log.Debug("plugin does not implement queries", "plugin", plugin)
				continue
			}
			m.log.Error("start query stream", "plugin", plugin, "error", err)
			continue
		}
		go m.handleQueryClient(plugin, db, client, q)
	}
}

// handleQueryClient handles a query client.
func (m *manager) handleQueryClient(plugin string, db storage.Storage, client clients.PluginClient, queries v1.Plugin_InjectQuerierClient) {
	defer func() {
		if err := queries.CloseSend(); err != nil {
			m.log.Error("close query stream", "plugin", plugin, "error", err)
		}
	}()
	// TODO: This does not support multiplexed queries yet.
	for {
		query, err := queries.Recv()
		if err != nil {
			if err == io.EOF {
				m.log.Debug("query stream closed cleanly", "plugin", plugin)
				return
			}
			// TODO: restart the stream?
			m.log.Error("receive query", "plugin", plugin, "error", err)
			return
		}
		m.log.Debug("handling plugin query", "plugin", plugin, "query", query.GetQuery(), "cmd", query.GetCommand().String())
		switch query.GetCommand() {
		case v1.PluginQuery_GET:
			var result v1.PluginQueryResult
			result.Id = query.GetId()
			result.Key = query.GetQuery()
			val, err := db.Get(queries.Context(), query.GetQuery())
			if err != nil {
				result.Error = err.Error()
			} else {
				result.Value = []string{val}
			}
			err = queries.Send(&result)
			if err != nil {
				m.log.Error("send query result", "plugin", plugin, "error", err)
			}
		case v1.PluginQuery_LIST:
			var result v1.PluginQueryResult
			result.Id = query.GetId()
			result.Key = query.GetQuery()
			keys, err := db.List(queries.Context(), query.GetQuery())
			if err != nil {
				result.Error = err.Error()
			} else {
				result.Value = keys
			}
			err = queries.Send(&result)
			if err != nil {
				m.log.Error("send query result", "plugin", plugin, "error", err)
			}
		case v1.PluginQuery_ITER:
			err := db.IterPrefix(queries.Context(), query.GetQuery(), func(key, val string) error {
				var result v1.PluginQueryResult
				result.Id = query.GetId()
				result.Key = key
				result.Value = []string{val}
				err := queries.Send(&result)
				return err
			})
			if err != nil {
				m.log.Error("stream query results", "plugin", plugin, "error", err)
				continue
			}
			var result v1.PluginQueryResult
			result.Id = query.GetId()
			result.Error = "EOF"
			err = queries.Send(&result)
			if err != nil {
				m.log.Error("send query results EOF", "plugin", plugin, "error", err)
			}
		default:
			var result v1.PluginQueryResult
			result.Id = query.GetId()
			result.Error = fmt.Sprintf("unsupported command: %v", query.GetCommand())
			err = queries.Send(&result)
			if err != nil {
				m.log.Error("send query result", "plugin", plugin, "error", err)
			}
		}
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

type authenticatedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authenticatedServerStream) Context() context.Context {
	return s.ctx
}
