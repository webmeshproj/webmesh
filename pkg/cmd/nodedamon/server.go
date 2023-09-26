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
package nodedaemon

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
	"github.com/multiformats/go-multiaddr"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/config"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	"github.com/webmeshproj/webmesh/pkg/meshnet/transport/libp2p"
	"github.com/webmeshproj/webmesh/pkg/meshnode"
	"github.com/webmeshproj/webmesh/pkg/services"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// AppDaemon is the app daemon RPC server.
type AppDaemon struct {
	v1.UnimplementedAppDaemonServer

	config     Config
	mesh       meshnode.Node
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
	// Take a copy of the base configuration and merge any overrides
	conf := *app.config.Config
	overrides := req.GetConfig().AsMap()
	k := koanf.New(".")
	err := k.Load(structs.Provider(conf, "koanf"), nil)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error loading configuration: %v", err)
	}
	if len(overrides) > 0 {
		err = k.Load(confmap.Provider(overrides, "koanf"), nil)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "error loading configuration overrides: %v", err)
		}
	}
	err = k.Unmarshal("", &conf)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error unmarshalling configuration: %v", err)
	}
	if req.GetDisableBootstrap() {
		conf.Bootstrap.Enabled = false
	}
	if req.GetJoinPsk() != "" {
		conf.Bootstrap.Enabled = false
		conf.Mesh.JoinAddress = ""
		conf.Discovery = config.DiscoveryOptions{
			Rendezvous: req.GetJoinPsk(),
			Discover:   true,
		}
	}
	err = conf.Validate()
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error validating configuration: %v", err)
	}
	// Time to go to work.
	log := app.log

	// Use a generic timeout for now
	ctx, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()
	ctx = context.WithLogger(ctx, log)

	log.Info("Starting mesh node")
	// Create a new mesh connection
	meshConfig, err := conf.NewMeshConfig(ctx, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create mesh config: %v", err)
	}
	meshConn := meshnode.New(meshConfig)
	storageProvider, err := conf.NewStorageProvider(ctx, meshConn, conf.Bootstrap.Force)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create storage provider: %v", err)
	}
	connectOpts, err := conf.NewConnectOptions(ctx, meshConn, storageProvider, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create connect options: %v", err)
	}
	// Start the storage provider
	err = storageProvider.Start(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to start storage provider: %v", err)
	}
	// Connect to the mesh
	err = meshConn.Connect(ctx, connectOpts)
	if err != nil {
		defer func() {
			err := storageProvider.Close()
			if err != nil {
				log.Error("failed to shutdown raft node", slog.String("error", err.Error()))
			}
		}()
		return nil, status.Errorf(codes.Internal, "failed to open mesh connection: %v", err)
	}
	select {
	case <-meshConn.Ready():
	case <-ctx.Done():
		return nil, status.Errorf(codes.Internal, "failed to start mesh node: %v", ctx.Err())
	}

	// If anything goes wrong at this point, make sure we close down cleanly.
	handleErr := func(cause error) error {
		if err := meshConn.Close(ctx); err != nil {
			log.Error("failed to shutdown mesh", slog.String("error", err.Error()))
		}
		return cause
	}
	log.Info("Mesh connection is ready, starting services")

	// Start the mesh services
	srvOpts, err := conf.NewServiceOptions(ctx, meshConn)
	if err != nil {
		return nil, handleErr(status.Errorf(codes.Internal, "failed to create service options: %v", err))
	}
	srv, err := services.NewServer(ctx, srvOpts)
	if err != nil {
		return nil, handleErr(status.Errorf(codes.Internal, "failed to create gRPC server: %v", err))
	}
	err = conf.RegisterAPIs(ctx, meshConn, srv)
	if err != nil {
		return nil, handleErr(status.Errorf(codes.Internal, "failed to register APIs: %v", err))
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Error("Mesh services failed", slog.String("error", err.Error()))
		}
	}()

	// Save the current mesh connection
	app.mesh = meshConn
	app.svcs = srv
	return &v1.ConnectResponse{
		NodeId:     meshConn.ID(),
		MeshDomain: meshConn.Domain(),
		Ipv4:       meshConn.Network().NetworkV4().String(),
		Ipv6:       meshConn.Network().NetworkV6().String(),
	}, nil
}

func (app *AppDaemon) Disconnect(ctx context.Context, _ *v1.DisconnectRequest) (*v1.DisconnectResponse, error) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.mesh == nil {
		return nil, ErrNotConnected
	}
	app.svcs.Shutdown(ctx)
	app.svcs = nil
	err := app.mesh.Close(ctx)
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
		val, err := app.mesh.Storage().MeshStorage().GetValue(stream.Context(), req.GetQuery())
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
		vals, err := app.mesh.Storage().MeshStorage().List(stream.Context(), req.GetQuery())
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
		err := app.mesh.Storage().MeshStorage().IterPrefix(stream.Context(), req.GetQuery(), func(key, value string) error {
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
	p, err := peers.New(app.mesh.Storage().MeshStorage()).Get(ctx, app.mesh.ID())
	if err != nil {
		return nil, err
	}
	return &v1.StatusResponse{
		ConnectionStatus: status,
		Node:             p.MeshNode,
	}, nil
}

func (app *AppDaemon) Publish(ctx context.Context, req *v1.PublishRequest) (*v1.PublishResponse, error) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.mesh == nil {
		return nil, ErrNotConnected
	}
	if storage.IsReservedPrefix(req.GetKey()) {
		return nil, status.Errorf(codes.InvalidArgument, "key %q is reserved", req.GetKey())
	}
	err := app.mesh.Storage().MeshStorage().PutValue(ctx, req.GetKey(), req.GetValue(), req.GetTtl().AsDuration())
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
	cancel, err := app.mesh.Storage().MeshStorage().Subscribe(srv.Context(), req.GetPrefix(), func(key, value string) {
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
	var peers []multiaddr.Multiaddr
	for _, addr := range req.GetBootstrapServers() {
		maddr, err := multiaddr.NewMultiaddr(addr)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid bootstrap peer address: %v", err)
		}
		peers = append(peers, maddr)
	}
	err := app.mesh.Discovery().AnnounceToDHT(ctx, libp2p.AnnounceOptions{
		Rendezvous: req.GetPsk(),
		HostOptions: libp2p.HostOptions{
			BootstrapPeers: peers,
			ConnectTimeout: time.Second * 5,
		},
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
	err := app.mesh.Discovery().LeaveDHT(ctx, req.GetPsk())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error leaving: %v", err)
	}
	return &v1.LeaveDHTResponse{}, nil
}
