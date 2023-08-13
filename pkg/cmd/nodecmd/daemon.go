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
	"syscall"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/services"
)

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

	srv := &AppDaemon{config: config}
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
		return nil, fmt.Errorf("invalid bind address: %s", bindAddr)
	}
}

// AppDaemon is the app daemon RPC server.
type AppDaemon struct {
	v1.UnimplementedAppDaemonServer
	config *Options
}

func (app *AppDaemon) Connect(ctx context.Context, req *v1.ConnectRequest) (*v1.ConnectResponse, error) {

	return nil, nil
}

func (app *AppDaemon) Disconnect(ctx context.Context, _ *v1.DisconnectRequest) (*v1.DisconnectResponse, error) {
	return nil, nil
}

func (app *AppDaemon) Metrics(ctx context.Context, _ *v1.MetricsRequest) (*v1.MetricsResponse, error) {
	return nil, nil
}

func (app *AppDaemon) Query(req *v1.QueryRequest, stream v1.AppDaemon_QueryServer) error {
	return nil
}

func (app *AppDaemon) StartCampfire(ctx context.Context, req *v1.StartCampfireRequest) (*v1.StartCampfireResponse, error) {
	return nil, nil
}

// DefaultDaemonSocket returns the default daemon socket path.
func DefaultDaemonSocket() string {
	if runtime.GOOS == "windows" {
		return "\\\\.\\pipe\\webmesh.sock"
	}
	return "/var/run/webmesh/webmesh.sock"
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
