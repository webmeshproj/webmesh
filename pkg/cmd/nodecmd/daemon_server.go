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

// Package nodecmd contains the entrypoint for webmesh nodes.
package nodecmd

import (
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/mitchellh/mapstructure"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/meshdb"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	"github.com/webmeshproj/webmesh/pkg/services"
)

// AppDaemon is the app daemon RPC server.
type AppDaemon struct {
	v1.UnimplementedAppDaemonServer

	config     *Options
	curConfig  *Options
	mesh       mesh.Mesh
	svcs       *services.Server
	connecting atomic.Bool
	mu         sync.Mutex
	log        *slog.Logger
}

var (
	// ErrNotConnected is returned when the node is not connected to the mesh.
	ErrNotConnected = status.Errorf(codes.FailedPrecondition, "not connected")
	// ErrAlreadyConnected is returned when the node is already connected to the mesh.
	ErrAlreadyConnected = status.Errorf(codes.FailedPrecondition, "already connected")
	// ErrAlreadyConnecting is returned when the node is already connecting to the mesh.
	ErrAlreadyConnecting = status.Errorf(codes.FailedPrecondition, "already connecting")
)

func (app *AppDaemon) Connect(ctx context.Context, req *v1.ConnectRequest) (*v1.ConnectResponse, error) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.mesh != nil {
		return nil, ErrAlreadyConnected
	} else if app.connecting.Load() {
		// The lock should keep this from ever happening, but just in case.
		return nil, ErrAlreadyConnecting
	}
	app.connecting.Store(true)
	defer app.connecting.Store(false)
	app.curConfig = app.config.DeepCopy()
	overrides := req.GetConfig().AsMap()
	if len(overrides) > 0 {
		err := mapstructure.Decode(overrides, app.curConfig)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "error decoding config overrides: %v", err)
		}
	}
	if req.GetDisableBootstrap() {
		app.curConfig.Mesh.Bootstrap.Enabled = false
	}
	if req.GetJoinPsk() != "" {
		app.curConfig.Mesh.Bootstrap.Enabled = false
		app.curConfig.Mesh.Mesh.JoinAddress = ""
		app.curConfig.Mesh.Discovery = &mesh.DiscoveryOptions{
			PSK:       req.GetJoinPsk(),
			UseKadDHT: true,
		}
	}
	err := app.curConfig.Validate()
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid config: %v", err)
	}
	conn, err := mesh.New(app.curConfig.Mesh)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error creating mesh: %v", err)
	}
	isRaftMember := func() bool {
		if app.curConfig.Mesh.Bootstrap != nil && app.curConfig.Mesh.Bootstrap.Enabled {
			return true
		}
		if app.curConfig.Mesh.Mesh != nil {
			return app.curConfig.Mesh.Mesh.JoinAsVoter || app.curConfig.Mesh.Mesh.JoinAsObserver
		}
		return false
	}()
	err = conn.Open(ctx, app.curConfig.Services.ToFeatureSet(isRaftMember))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error opening mesh: %v", err)
	}
	app.mesh = conn
	app.svcs, err = services.NewServer(conn, app.curConfig.Services)
	if err != nil {
		cerr := conn.Close()
		app.mesh = nil
		app.svcs = nil
		if cerr != nil {
			return nil, status.Errorf(codes.Internal, "error creating services: %v (error closing mesh: %v)", err, cerr)
		}
		return nil, status.Errorf(codes.Internal, "error creating services: %v", err)
	}
	go func() {
		err := app.svcs.ListenAndServe()
		if err != nil {
			app.log.Error("Error serving services", "err", err.Error())
			// TODO: Dispatch to the client.
		}
	}()
	return &v1.ConnectResponse{
		NodeId:     app.mesh.ID(),
		MeshDomain: app.mesh.Domain(),
		Ipv4:       app.mesh.Network().WireGuard().AddressV4().String(),
		Ipv6:       app.mesh.Network().WireGuard().AddressV6().String(),
	}, nil
}

func (app *AppDaemon) Disconnect(ctx context.Context, _ *v1.DisconnectRequest) (*v1.DisconnectResponse, error) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.mesh == nil {
		return nil, ErrNotConnected
	}
	app.svcs.Stop()
	app.svcs = nil
	err := app.mesh.Close()
	app.mesh = nil
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error while disconnecting from mesh: %v", err)
	}
	return &v1.DisconnectResponse{}, nil
}

func (app *AppDaemon) Metrics(ctx context.Context, _ *v1.MetricsRequest) (*v1.MetricsResponse, error) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.mesh == nil {
		return nil, ErrNotConnected
	}
	metrics, err := app.mesh.Network().WireGuard().Metrics()
	if err != nil {
		return nil, err
	}
	return &v1.MetricsResponse{
		Interfaces: map[string]*v1.InterfaceMetrics{
			metrics.DeviceName: metrics,
		},
	}, nil
}

func (app *AppDaemon) Query(req *v1.QueryRequest, stream v1.AppDaemon_QueryServer) error {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.mesh == nil {
		return ErrNotConnected
	}
	switch req.GetCommand() {
	case v1.QueryRequest_GET:
		var result v1.QueryResponse
		result.Key = req.GetQuery()
		val, err := app.mesh.Storage().GetValue(stream.Context(), req.GetQuery())
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Value = []string{val}
		}
		err = stream.Send(&result)
		if err != nil {
			return err
		}
	case v1.QueryRequest_LIST:
		var result v1.QueryResponse
		result.Key = req.GetQuery()
		vals, err := app.mesh.Storage().List(stream.Context(), req.GetQuery())
		if err != nil {
			result.Error = err.Error()
		} else {
			result.Value = vals
		}
		err = stream.Send(&result)
		if err != nil {
			return err
		}
	case v1.QueryRequest_ITER:
		err := app.mesh.Storage().IterPrefix(stream.Context(), req.GetQuery(), func(key, value string) error {
			var result v1.QueryResponse
			result.Key = key
			result.Value = []string{value}
			return stream.Send(&result)
		})
		if err != nil {
			return err
		}
		var result v1.QueryResponse
		result.Error = "EOF"
		return stream.Send(&result)
	}
	return status.Errorf(codes.Unimplemented, "unknown query command: %v", req.GetCommand())
}

func (app *AppDaemon) Status(ctx context.Context, _ *v1.StatusRequest) (*v1.StatusResponse, error) {
	var status v1.StatusResponse_ConnectionStatus
	if app.mesh == nil {
		return &v1.StatusResponse{
			ConnectionStatus: v1.StatusResponse_DISCONNECTED,
		}, nil
	}
	if app.connecting.Load() {
		return &v1.StatusResponse{
			ConnectionStatus: v1.StatusResponse_CONNECTING,
		}, nil
	}
	// We are connected
	app.mu.Lock()
	defer app.mu.Unlock()
	// Check if we got disconnected before we hit this point
	if app.mesh == nil {
		return &v1.StatusResponse{
			ConnectionStatus: v1.StatusResponse_DISCONNECTED,
		}, nil
	}
	var raftStatus v1.ClusterStatus
	if app.mesh.Raft().IsLeader() {
		raftStatus = v1.ClusterStatus_CLUSTER_LEADER
	} else if app.mesh.Raft().IsVoter() {
		raftStatus = v1.ClusterStatus_CLUSTER_VOTER
	} else {
		raftStatus = v1.ClusterStatus_CLUSTER_NON_VOTER
	}
	p, err := peers.New(app.mesh.Storage()).Get(ctx, app.mesh.ID())
	if err != nil {
		return nil, err
	}
	return &v1.StatusResponse{
		ConnectionStatus: status,
		Node:             p.Proto(raftStatus),
	}, nil
}

func (app *AppDaemon) Publish(ctx context.Context, req *v1.PublishRequest) (*v1.PublishResponse, error) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.mesh == nil {
		return nil, ErrNotConnected
	}
	if meshdb.IsReservedPrefix(req.GetKey()) {
		return nil, status.Errorf(codes.InvalidArgument, "key %q is reserved", req.GetKey())
	}
	err := app.mesh.Storage().PutValue(ctx, req.GetKey(), req.GetValue(), req.GetTtl().AsDuration())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error publishing: %v", err)
	}
	return &v1.PublishResponse{}, nil
}

func (app *AppDaemon) Subscribe(req *v1.SubscribeRequest, srv v1.AppDaemon_SubscribeServer) error {
	app.mu.Lock()
	if app.mesh == nil {
		app.mu.Unlock()
		return ErrNotConnected
	}
	cancel, err := app.mesh.Storage().Subscribe(srv.Context(), req.GetPrefix(), func(key, value string) {
		err := srv.Send(&v1.SubscriptionEvent{
			Key:   key,
			Value: value,
		})
		if err != nil {
			app.log.Error("error sending subscription event", "error", err.Error())
		}
	})
	app.mu.Unlock()
	if err != nil {
		return status.Errorf(codes.Internal, "error subscribing: %v", err)
	}
	defer cancel()
	<-srv.Context().Done()
	return nil
}

func (app *AppDaemon) AnnounceDHT(ctx context.Context, req *v1.AnnounceDHTRequest) (*v1.AnnounceDHTResponse, error) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.mesh == nil {
		return nil, ErrNotConnected
	}
	err := app.mesh.AnnounceDHT(ctx, &mesh.DiscoveryOptions{
		PSK:                 req.GetPsk(),
		KadBootstrapServers: req.GetBootstrapServers(),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error announcing: %v", err)
	}
	return &v1.AnnounceDHTResponse{}, nil
}

func (app *AppDaemon) LeaveDHT(ctx context.Context, req *v1.LeaveDHTRequest) (*v1.LeaveDHTResponse, error) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.mesh == nil {
		return nil, ErrNotConnected
	}
	err := app.mesh.LeaveDHT(ctx, req.GetPsk())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error leaving: %v", err)
	}
	return &v1.LeaveDHTResponse{}, nil
}
