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
	"time"

	"github.com/fullstorydev/grpcui/standalone"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/logging"
)

// Run runs the app daemon with the given configuration. The context
// can be used to shutdown the server, otherwise it will wait for a
// SIGINT or SIGTERM.
func Run(ctx context.Context, conf Config) error {
	log := logging.NewLogger(conf.LogLevel, "text")
	// Setup the listener
	listener, err := newListener(conf.Bind, conf.InsecureSocket)
	if err != nil {
		return err
	}
	defer listener.Close()
	// Setup the server
	srv := NewServer(log)
	defer srv.Close()
	unarymiddlewares := []grpc.UnaryServerInterceptor{
		context.LogInjectUnaryServerInterceptor(log),
		logging.ContextUnaryServerInterceptor(),
	}
	streammiddlewares := []grpc.StreamServerInterceptor{
		context.LogInjectStreamServerInterceptor(log),
		logging.ContextStreamServerInterceptor(),
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
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		defer cancel()
		select {
		case <-sig:
		case <-ctx.Done():
		}
	}()
	if conf.UI.Enabled {
		go runWebUI(ctx, log, listener, conf.UI.ListenAddress)
	}
	if conf.GRPCWeb {
		return runGRPCWebServer(ctx, log, grpcServer, listener)
	}
	return runGRPCServer(ctx, log, grpcServer, listener)
}

func runGRPCServer(ctx context.Context, log *slog.Logger, srv *grpc.Server, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		log.Info("Shutting down gRPC app daemon")
		srv.GracefulStop()
	}()
	log.Info("Serving gRPC app daemon", "bind-addr", ln.Addr())
	return srv.Serve(ln)
}

func runGRPCWebServer(ctx context.Context, log *slog.Logger, srv *grpc.Server, ln net.Listener) error {
	wrapped := grpcweb.WrapServer(srv, grpcweb.WithWebsockets(true))
	httpSrv := &http.Server{
		Handler: http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			if wrapped.IsGrpcWebRequest(req) {
				wrapped.ServeHTTP(resp, req)
				return
			}
			// Fall down to the gRPC server
			srv.ServeHTTP(resp, req)
		}),
	}
	go func() {
		<-ctx.Done()
		log.Info("Shutting down gRPC-Web app daemon")
		err := httpSrv.Shutdown(context.Background())
		if err != nil {
			log.Error("Error shutting down gRPC-Web app daemon", "err", err)
		}
	}()
	log.Info("Serving gRPC-Web app daemon", "bind-addr", ln.Addr())
	err := httpSrv.Serve(ln)
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func runWebUI(ctx context.Context, log *slog.Logger, srvln net.Listener, laddr string) {
	// Dial the local listener for the gRPC server
	log = log.With("ui", "grpcui")
	var handler http.Handler
	var err error
	for i := 0; i < 10; i++ {
		var c *grpc.ClientConn
		c, err = grpc.DialContext(ctx, srvln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Debug("Error dialing gRPC server", "err", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		defer c.Close()
		handler, err = standalone.HandlerViaReflection(ctx, c, srvln.Addr().String())
		if err != nil {
			log.Debug("Error creating gRPC UI handler", "err", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		break
	}
	if err != nil {
		log.Error("Error setting up gRPC UI", "err", err)
		return
	}
	ln, err := net.Listen("tcp", laddr)
	if err != nil {
		log.Error("Error listening for gRPC UI", "err", err)
		return
	}
	httpSrv := &http.Server{Handler: handler}
	go func() {
		<-ctx.Done()
		log.Info("Shutting down gRPC UI server")
		err := httpSrv.Shutdown(context.Background())
		if err != nil {
			log.Error("Error shutting down gRPC UI server", "err", err)
		}
	}()
	log.Info("Serving gRPC UI server", "bind-addr", ln.Addr())
	err = httpSrv.Serve(ln)
	if err != nil && err != http.ErrServerClosed {
		log.Error("Error serving gRPC UI server", "err", err)
	}
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
