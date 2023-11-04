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

package daemoncmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/bufbuild/protovalidate-go"
	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage/rpcsrv"
)

// AppDaemon is the app daemon RPC server.
type AppDaemon struct {
	v1.UnimplementedAppDaemonServer
	connmgr   *ConnManager
	validator *protovalidate.Validator
	log       *slog.Logger
}

// NewServer returns a new AppDaemon server.
func NewServer(conf Config) (*AppDaemon, error) {
	v, err := protovalidate.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create validator: %w", err)
	}
	connmgr, err := NewConnManager(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}
	return &AppDaemon{
		connmgr:   connmgr,
		validator: v,
		log:       conf.NewLogger().With("appdaemon", "server"),
	}, nil
}

func (app *AppDaemon) Connect(ctx context.Context, req *v1.ConnectRequest) (*v1.ConnectResponse, error) {
	err := app.validator.Validate(req)
	if err != nil {
		return nil, newInvalidError(err)
	}
	connID, node, err := app.connmgr.NewConn(ctx, req)
	if err != nil {
		return nil, err
	}
	app.log.Info("Starting node", "id", connID)
	err = node.Start(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to start node: %v", err)
	}
	return &v1.ConnectResponse{
		Id:          connID,
		NodeID:      string(node.MeshNode().ID()),
		MeshDomain:  node.MeshNode().Domain(),
		Ipv4Address: node.MeshNode().Network().WireGuard().AddressV4().String(),
		Ipv6Address: node.MeshNode().Network().WireGuard().AddressV6().String(),
		Ipv4Network: node.MeshNode().Network().NetworkV4().String(),
		Ipv6Network: node.MeshNode().Network().NetworkV6().String(),
	}, nil
}

func (app *AppDaemon) Disconnect(ctx context.Context, req *v1.DisconnectRequest) (*v1.DisconnectResponse, error) {
	err := app.validator.Validate(req)
	if err != nil {
		return nil, newInvalidError(err)
	}
	return &v1.DisconnectResponse{}, app.connmgr.Disconnect(ctx, req.GetId())
}

func (app *AppDaemon) Metrics(ctx context.Context, req *v1.MetricsRequest) (*v1.MetricsResponse, error) {
	err := app.validator.Validate(req)
	if err != nil {
		return nil, newInvalidError(err)
	}
	ids := req.GetIds()
	if len(ids) > 0 {
		for _, id := range req.GetIds() {
			_, ok := app.connmgr.Get(id)
			if !ok {
				return nil, ErrNotConnected
			}
		}
	}
	if len(ids) == 0 {
		ids = app.connmgr.ConnIDs()
	}
	app.log.Info("Getting metrics for connections", "ids", ids)
	res := &v1.MetricsResponse{
		Interfaces: make(map[string]*v1.InterfaceMetrics),
	}
	for _, i := range ids {
		id := i
		conn, ok := app.connmgr.Get(id)
		if !ok {
			// Disconnect was called on a connection before we got here.
			continue
		}
		if !conn.MeshNode().Started() {
			res.Interfaces[id] = &v1.InterfaceMetrics{}
			continue
		}
		metrics, err := conn.MeshNode().Network().WireGuard().Metrics()
		if err != nil {
			app.log.Error("Error getting metrics for connection", "id", id, "error", err.Error())
			continue
		}
		res.Interfaces[id] = metrics
	}
	return res, nil
}

func (app *AppDaemon) Status(ctx context.Context, req *v1.StatusRequest) (*v1.StatusResponse, error) {
	err := app.validator.Validate(req)
	if err != nil {
		return nil, newInvalidError(err)
	}
	ids := req.GetIds()
	if len(ids) == 0 {
		ids = app.connmgr.ConnIDs()
	}
	res := &v1.StatusResponse{
		Statuses: make(map[string]*v1.ConnectionStatus),
	}
	for _, connid := range ids {
		id := connid
		app.log.Info("Retrieving status for connection", "id", id)
		c, ok := app.connmgr.Get(id)
		if !ok {
			app.log.Info("Status requested for unknown connection", "id", id)
			res.Statuses[id] = &v1.ConnectionStatus{
				ConnectionStatus: v1.ConnectionStatus_DISCONNECTED,
			}
		} else {
			res.Statuses[id] = &v1.ConnectionStatus{
				ConnectionStatus: func() v1.ConnectionStatus_Status {
					if c.MeshNode().Started() {
						return v1.ConnectionStatus_CONNECTED
					}
					return v1.ConnectionStatus_CONNECTING
				}(),
				Node: func() *v1.MeshNode {
					if !c.MeshNode().Started() {
						return nil
					}
					node, err := c.MeshNode().Storage().MeshDB().Peers().Get(ctx, c.MeshNode().ID())
					if err != nil {
						app.log.Error("Error getting node from storage", "id", c.MeshNode().ID(), "error", err.Error())
						return nil
					}
					return node.MeshNode
				}(),
			}
		}
	}
	return res, nil
}

func (app *AppDaemon) Query(ctx context.Context, req *v1.AppQueryRequest) (*v1.QueryResponse, error) {
	err := app.validator.Validate(req)
	if err != nil {
		return nil, newInvalidError(err)
	}
	conn, ok := app.connmgr.Get(req.GetId())
	if !ok {
		return nil, ErrNotConnected
	}
	if !conn.MeshNode().Started() {
		return nil, ErrNotConnected
	}
	app.log.Info("Querying storage for connection", "id", req.GetId())
	return rpcsrv.ServeQuery(ctx, conn.MeshNode().Storage(), req.GetQuery()), nil
}

func (app *AppDaemon) Drop(ctx context.Context, req *v1.AppDropRequest) (*v1.AppDropResponse, error) {
	_, ok := app.connmgr.Get(req.GetId())
	if ok {
		return nil, ErrConnected
	}
	datadir := app.connmgr.DataDir(req.GetId())
	app.log.Info("Dropping storage for connection", "id", req.GetId(), "datadir", datadir)
	err := os.RemoveAll(datadir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to drop storage: %v", err)
	}
	return &v1.AppDropResponse{}, nil
}

func (app *AppDaemon) Close() error {
	return app.connmgr.Close()
}

func newInvalidError(err error) error {
	return status.Errorf(codes.InvalidArgument, err.Error())
}
