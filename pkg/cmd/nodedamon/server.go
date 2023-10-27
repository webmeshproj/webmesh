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

	v1 "github.com/webmeshproj/api/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
)

// AppDaemon is the app daemon RPC server.
type AppDaemon struct {
	v1.UnimplementedAppDaemonServer
	log *slog.Logger
}

var (
	// ErrNotConnected is returned when the node is not connected to the mesh.
	ErrNotConnected = status.Errorf(codes.FailedPrecondition, "not connected")
	// ErrAlreadyConnected is returned when the node is already connected to the mesh.
	ErrAlreadyConnected = status.Errorf(codes.FailedPrecondition, "already connected")
)

// NewServer returns a new AppDaemon server.
func NewServer(log *slog.Logger) *AppDaemon {
	return &AppDaemon{log: log}
}

func (app *AppDaemon) Connect(ctx context.Context, req *v1.ConnectRequest) (*v1.ConnectResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")
}

func (app *AppDaemon) Disconnect(ctx context.Context, req *v1.DisconnectRequest) (*v1.DisconnectResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")

}

func (app *AppDaemon) Metrics(ctx context.Context, req *v1.MetricsRequest) (*v1.MetricsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")

}

func (app *AppDaemon) Query(ctx context.Context, req *v1.QueryRequest) (*v1.QueryResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")

}

func (app *AppDaemon) Status(ctx context.Context, req *v1.StatusRequest) (*v1.StatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")

}

func (app *AppDaemon) Publish(ctx context.Context, req *v1.PublishRequest) (*v1.PublishResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "not implemented")

}

func (app *AppDaemon) Subscribe(req *v1.SubscribeRequest, srv v1.AppDaemon_SubscribeServer) error {
	return status.Errorf(codes.Unimplemented, "not implemented")

}

func (app *AppDaemon) Close() error {
	return nil
}
