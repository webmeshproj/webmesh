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

// Package nodedaemon contains the entrypoint for webmesh nodes running as an application daemon.
package nodedaemon

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

	"github.com/webmeshproj/webmesh/pkg/cmd/config"
	"github.com/webmeshproj/webmesh/pkg/context"
)

// Config is the configuration for the applicaton daeemon.
type Config struct {
	// Bind is the bind address for the daemon.
	Bind string
	// InsecureSocket uses an insecure socket when binding to a unix socket.
	InsecureSocket bool
	// GRPCWeb enables gRPC-Web support.
	GRPCWeb bool
	// Config is the configuration of the node.
	Config *config.Config
}

// DefaultDaemonSocket returns the default daemon socket path.
func DefaultDaemonSocket() string {
	if runtime.GOOS == "windows" {
		return "\\\\.\\pipe\\webmesh.sock"
	}
	return "/var/run/webmesh/webmesh.sock"
}

// Run runs the app daemon with the given configuration. The context
// can be used to shutdown the server, otherwise it will wait for a
// SIGINT or SIGTERM.
func Run(ctx context.Context, conf Config) error {
	log := slog.Default()

	// Setup the listener

	listener, err := newListener(conf.Bind, conf.InsecureSocket)
	if err != nil {
		return err
	}
	defer listener.Close()

	// Setup the server

	srv := &AppDaemon{config: conf, log: log.With("component", "app-daemon")}
	unarymiddlewares := []grpc.UnaryServerInterceptor{
		context.LogInjectUnaryServerInterceptor(log),
		logging.UnaryServerInterceptor(config.InterceptorLogger(), logging.WithLogOnEvents(logging.StartCall, logging.FinishCall)),
	}
	streammiddlewares := []grpc.StreamServerInterceptor{
		context.LogInjectStreamServerInterceptor(log),
		logging.StreamServerInterceptor(config.InterceptorLogger(), logging.WithLogOnEvents(logging.StartCall, logging.FinishCall)),
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

	if conf.GRPCWeb {
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
			srv.mu.Lock()
			defer srv.mu.Unlock()
			if srv.mesh != nil {
				err := srv.mesh.Close(ctx)
				if err != nil {
					log.Error("Error disconnecting from the mesh", "err", err)
				}
			}
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
		srv.mu.Lock()
		defer srv.mu.Unlock()
		if srv.mesh != nil {
			err := srv.mesh.Close(ctx)
			if err != nil {
				log.Error("Error disconnecting from the mesh", "err", err)
			}
		}
		grpcServer.GracefulStop()
	}()

	log.Info("Serving gRPC app daemon", "bind-addr", listener.Addr())
	return grpcServer.Serve(listener)
}

func newListener(bindAddr string, insecure bool) (net.Listener, error) {
	if bindAddr == "" {
		bindAddr = DefaultDaemonSocket()
	}
	switch {
	case strings.HasPrefix(bindAddr, "/"), strings.HasPrefix(bindAddr, "\\\\"):
		// Unix socket
		return newUnixSocket(bindAddr, insecure)
	case strings.HasPrefix(bindAddr, "unix://"):
		// Unix socket
		return newUnixSocket(bindAddr[7:], insecure)
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
