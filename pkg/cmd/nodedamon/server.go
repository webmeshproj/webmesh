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
	"fmt"
	"log/slog"
	"sync"

	"github.com/bufbuild/protovalidate-go"
	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/embed"
	"github.com/webmeshproj/webmesh/pkg/logging"
)

// AppDaemon is the app daemon RPC server.
type AppDaemon struct {
	v1.UnimplementedAppDaemonServer
	conns map[string]embed.Node
	key   crypto.PrivateKey
	val   *protovalidate.Validator
	log   *slog.Logger
	mu    sync.Mutex
}

var (
	// ErrNotConnected is returned when the node is not connected to the mesh.
	ErrNotConnected = status.Errorf(codes.FailedPrecondition, "not connected")
	// ErrAlreadyConnected is returned when the node is already connected to the mesh.
	ErrAlreadyConnected = status.Errorf(codes.FailedPrecondition, "already connected")
)

// NewServer returns a new AppDaemon server.
func NewServer(conf Config) (*AppDaemon, error) {
	v, err := protovalidate.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create validator: %w", err)
	}
	key, err := conf.LoadKey()
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}
	return &AppDaemon{
		conns: make(map[string]embed.Node),
		key:   key,
		val:   v,
		log:   logging.NewLogger(conf.LogLevel, "text").With("appdaemon", "server"),
	}, nil
}

func (app *AppDaemon) Connect(ctx context.Context, req *v1.ConnectRequest) (*v1.ConnectResponse, error) {
	err := app.val.Validate(req)
	if err != nil {
		return nil, newInvalidError(err)
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}

func (app *AppDaemon) Disconnect(ctx context.Context, req *v1.DisconnectRequest) (*v1.DisconnectResponse, error) {
	err := app.val.Validate(req)
	if err != nil {
		return nil, newInvalidError(err)
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	return nil, status.Errorf(codes.Unimplemented, "not implemented")

}

func (app *AppDaemon) Metrics(ctx context.Context, req *v1.MetricsRequest) (*v1.MetricsResponse, error) {
	err := app.val.Validate(req)
	if err != nil {
		return nil, newInvalidError(err)
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	return nil, status.Errorf(codes.Unimplemented, "not implemented")

}

func (app *AppDaemon) Query(ctx context.Context, req *v1.QueryRequest) (*v1.QueryResponse, error) {
	err := app.val.Validate(req)
	if err != nil {
		return nil, newInvalidError(err)
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	return nil, status.Errorf(codes.Unimplemented, "not implemented")

}

func (app *AppDaemon) Status(ctx context.Context, req *v1.StatusRequest) (*v1.StatusResponse, error) {
	err := app.val.Validate(req)
	if err != nil {
		return nil, newInvalidError(err)
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	return nil, status.Errorf(codes.Unimplemented, "not implemented")

}

func (app *AppDaemon) Publish(ctx context.Context, req *v1.PublishRequest) (*v1.PublishResponse, error) {
	err := app.val.Validate(req)
	if err != nil {
		return nil, newInvalidError(err)
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	return nil, status.Errorf(codes.Unimplemented, "not implemented")

}

func (app *AppDaemon) Subscribe(req *v1.SubscribeRequest, srv v1.AppDaemon_SubscribeServer) error {
	err := app.val.Validate(req)
	if err != nil {
		return newInvalidError(err)
	}
	app.mu.Lock()
	defer app.mu.Unlock()
	return status.Errorf(codes.Unimplemented, "not implemented")

}

func (app *AppDaemon) Close() error {
	app.mu.Lock()
	defer app.mu.Unlock()
	for _, conn := range app.conns {
		err := conn.Stop(context.WithLogger(context.Background(), app.log))
		if err != nil {
			app.log.Error("Error stopping node", "err", err)
		}
	}
	app.conns = nil
	return nil
}

func newInvalidError(err error) error {
	return status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
}
