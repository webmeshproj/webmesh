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
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"github.com/mitchellh/mapstructure"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/campfire"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/services"
)

var (
	// ErrNotConnected is returned when the node is not connected to the mesh.
	ErrNotConnected = status.Errorf(codes.FailedPrecondition, "not connected")
	// ErrAlreadyConnected is returned when the node is already connected to the mesh.
	ErrAlreadyConnected = status.Errorf(codes.FailedPrecondition, "already connected")
)

// DefaultDaemonSocket returns the default daemon socket path.
func DefaultDaemonSocket() string {
	if runtime.GOOS == "windows" {
		return "\\\\.\\pipe\\webmesh.sock"
	}
	return "/var/run/webmesh/webmesh.sock"
}

// RunAppDaemon runs the app daemon.
func RunAppDaemon(ctx context.Context, config *Options) error {
	log := slog.Default()

	// Setup the listener

	listener, err := newListener()
	if err != nil {
		return err
	}
	defer listener.Close()

	// Setup the server

	srv := &AppDaemon{config: config, log: log.With("component", "app-daemon")}
	unarymiddlewares := []grpc.UnaryServerInterceptor{
		context.LogInjectUnaryServerInterceptor(log),
		logging.UnaryServerInterceptor(services.InterceptorLogger(), logging.WithLogOnEvents(logging.StartCall, logging.FinishCall)),
	}
	streammiddlewares := []grpc.StreamServerInterceptor{
		context.LogInjectStreamServerInterceptor(log),
		logging.StreamServerInterceptor(services.InterceptorLogger(), logging.WithLogOnEvents(logging.StartCall, logging.FinishCall)),
	}
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(unarymiddlewares...),
		grpc.ChainStreamInterceptor(streammiddlewares...),
	)
	v1.RegisterAppDaemonServer(grpcServer, srv)
	reflection.Register(grpcServer)

	// Time to go to work

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	if *appDaemonGrpcWeb {
		wrapped := grpcweb.WrapServer(grpcServer, grpcweb.WithWebsockets(true))
		httpSrv := &http.Server{
			Handler: http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
				if wrapped.IsGrpcWebRequest(req) {
					wrapped.ServeHTTP(resp, req)
					return
				}
				// Fall back to other servers.
				http.DefaultServeMux.ServeHTTP(resp, req)
			}),
		}
		go func() {
			select {
			case <-ctx.Done():
			case <-sig:
			}
			log.Info("Shutting down gRPC-Web app daemon")
			err := httpSrv.Shutdown(context.Background())
			if err != nil {
				log.Error("Error shutting down gRPC-Web app daemon", "err", err)
			}
		}()
		log.Info("Serving gRPC-Web app daemon", "bind-addr", listener.Addr())
		err := httpSrv.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	}

	go func() {
		select {
		case <-ctx.Done():
		case <-sig:
		}
		log.Info("Shutting down gRPC app daemon")
		grpcServer.GracefulStop()
	}()

	log.Info("Serving gRPC app daemon", "bind-addr", listener.Addr())
	return grpcServer.Serve(listener)
}

// AppDaemon is the app daemon RPC server.
type AppDaemon struct {
	v1.UnimplementedAppDaemonServer
	config    *Options
	curConfig *Options
	mesh      mesh.Mesh
	svcs      *services.Server
	mu        sync.Mutex
	log       *slog.Logger
}

func (app *AppDaemon) Connect(ctx context.Context, req *v1.ConnectRequest) (*v1.ConnectResponse, error) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.mesh != nil {
		return nil, ErrAlreadyConnected
	}
	app.curConfig = app.config.DeepCopy()
	overrides := req.GetConfig().AsMap()
	if len(overrides) > 0 {
		err := mapstructure.Decode(app.curConfig, overrides)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "error decoding config overrides: %v", err)
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
	err = conn.Open(ctx, app.curConfig.Services.ToFeatureSet())
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
	return &v1.ConnectResponse{}, nil
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
		val, err := app.mesh.Storage().Get(stream.Context(), req.GetQuery())
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

func (app *AppDaemon) StartCampfire(ctx context.Context, req *v1.StartCampfireRequest) (*v1.StartCampfireResponse, error) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.mesh == nil {
		return nil, ErrNotConnected
	}
	if req.GetCampUrl() == "" {
		if !app.curConfig.Services.TURN.Enabled && !app.curConfig.Services.TURN.CampfireEnabled {
			return nil, status.Error(codes.InvalidArgument, "Campfire TURN is not enabled on this node")
		}
		turnServer := "turn:" + app.curConfig.Services.TURN.PublicIP + ":" + strconv.Itoa(app.curConfig.Services.TURN.ListenPort)
		psk, err := campfire.GeneratePSK()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "error generating PSK: %v", err)
		}
		uri := &campfire.CampfireURI{
			PSK:         psk,
			TURNServers: []string{turnServer},
		}
		req.CampUrl = uri.EncodeURI()
	}
	parsed, err := campfire.ParseCampfireURI(req.GetCampUrl())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error parsing campfire URI: %v", err)
	}
	err = app.mesh.StartCampfire(ctx, campfire.Options{
		PSK:         parsed.PSK,
		TURNServers: parsed.TURNServers,
	}, nil)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error starting campfire: %v", err)
	}
	return &v1.StartCampfireResponse{
		CampUrl: req.GetCampUrl(),
	}, nil
}

func (app *AppDaemon) LeaveCampfire(ctx context.Context, req *v1.LeaveCampfireRequest) (*v1.LeaveCampfireResponse, error) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.mesh == nil {
		return nil, ErrNotConnected
	}
	parsed, err := campfire.ParseCampfireURI(req.GetCampUrl())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error parsing campfire URI: %v", err)
	}
	err = app.mesh.LeaveCampfire(ctx, string(parsed.PSK))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error leaving campfire: %v", err)
	}
	return &v1.LeaveCampfireResponse{}, nil
}

func newListener() (net.Listener, error) {
	bindAddr := *appDaemonBind
	if bindAddr == "" {
		bindAddr = DefaultDaemonSocket()
	}
	switch {
	case strings.HasPrefix(bindAddr, "/"), strings.HasPrefix(bindAddr, "\\\\"):
		// Unix socket
		return newUnixSocket(bindAddr, *appDaemonInsecureSocket)
	case strings.HasPrefix(bindAddr, "unix://"):
		// Unix socket
		return newUnixSocket(bindAddr[7:], *appDaemonInsecureSocket)
	case strings.HasPrefix(bindAddr, "tcp://"):
		// TCP socket
		return net.Listen("tcp", bindAddr[6:])
	default:
		// Default to TCP socket
		return net.Listen("tcp", bindAddr)
	}
}

func newUnixSocket(socketPath string, insecure bool) (net.Listener, error) {
	if runtime.GOOS != "windows" {
		// Ensure the socket directory exists.
		sockDir := filepath.Dir(socketPath)
		if err := os.MkdirAll(sockDir, 0750); err != nil {
			return nil, err
		}
		// Ensure the socket directory has the correct permissions.
		var dirMode fs.FileMode = 0750
		if insecure {
			dirMode = 0755
		}
		if err := os.Chmod(sockDir, dirMode); err != nil {
			return nil, fmt.Errorf("chmod unix socket directory: %w", err)
		}
		// Change the group ownership to the webmesh group if it exists.
		group, err := user.LookupGroup("webmesh")
		if err == nil {
			gid, err := strconv.Atoi(group.Gid)
			if err != nil {
				return nil, fmt.Errorf("invalid gid: %w", err)
			}
			err = os.Chown(sockDir, -1, gid)
			if err != nil {
				return nil, fmt.Errorf("chown unix socket directory: %w", err)
			}
		}
		// Remove any existing socket file.
		if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	return net.Listen("unix", socketPath)
}
