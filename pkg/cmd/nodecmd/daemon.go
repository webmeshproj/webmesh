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
	"context"

	v1 "github.com/webmeshproj/api/v1"
)

// RunAppDaemon runs the app daemon.
func RunAppDaemon(ctx context.Context, config *Options) error {
	return nil
}

// AppDaemon is the app daemon RPC server.
type AppDaemon struct {
	v1.UnimplementedAppDaemonServer
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
