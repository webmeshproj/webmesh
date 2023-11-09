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
	"runtime"
	"time"

	"github.com/bufbuild/protovalidate-go"
	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/storage/errors"
	"github.com/webmeshproj/webmesh/pkg/storage/rpcsrv"
	"github.com/webmeshproj/webmesh/pkg/version"
)

// AppDaemon is the app daemon RPC server.
type AppDaemon struct {
	v1.UnimplementedAppDaemonServer
	started   time.Time
	version   version.BuildInfo
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
		started:   time.Now(),
		version:   version.GetBuildInfo(),
		connmgr:   connmgr,
		validator: v,
		log:       conf.NewLogger().With("appdaemon", "server"),
	}, nil
}

func (app *AppDaemon) Close() error {
	return app.connmgr.Close()
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
		defer app.connmgr.RemoveConn(connID)
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

func (app *AppDaemon) PutConnection(ctx context.Context, req *v1.PutConnectionRequest) (*v1.PutConnectionResponse, error) {
	err := app.validator.Validate(req)
	if err != nil {
		return nil, newInvalidError(err)
	}
	err = app.connmgr.Profiles().Put(ctx, ProfileID(req.GetId()), Profile{req.GetParameters()})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to store connection: %v", err)
	}
	return &v1.PutConnectionResponse{}, nil
}

func (app *AppDaemon) GetConnection(ctx context.Context, req *v1.GetConnectionRequest) (*v1.GetConnectionResponse, error) {
	err := app.validator.Validate(req)
	if err != nil {
		return nil, newInvalidError(err)
	}
	conn, err := app.connmgr.Profiles().Get(ctx, ProfileID(req.GetId()))
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, status.Errorf(codes.NotFound, "connection not found: %v", err)
		}
		return nil, status.Errorf(codes.Internal, "failed to get connection: %v", err)
	}
	connStatus := app.connmgr.GetStatus(req.GetId())
	var node *v1.MeshNode
	if connStatus == v1.DaemonConnStatus_CONNECTED {
		meshNode, err := app.connmgr.GetMeshNode(ctx, req.GetId())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to get mesh node: %v", err)
		}
		node = meshNode.MeshNode
	}
	return &v1.GetConnectionResponse{
		Parameters: conn.ConnectionParameters,
		Status:     connStatus,
		Node:       node,
	}, nil
}

func (app *AppDaemon) DropConnection(ctx context.Context, req *v1.DropConnectionRequest) (*v1.DropConnectionResponse, error) {
	err := app.validator.Validate(req)
	if err != nil {
		return nil, newInvalidError(err)
	}
	err = app.connmgr.DropStorage(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	err = app.connmgr.Profiles().Delete(ctx, ProfileID(req.GetId()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete connection: %v", err)
	}
	return &v1.DropConnectionResponse{}, nil
}

func (app *AppDaemon) ListConnections(ctx context.Context, req *v1.ListConnectionsRequest) (*v1.ListConnectionsResponse, error) {
	err := app.validator.Validate(req)
	if err != nil {
		return nil, newInvalidError(err)
	}
	ids := req.GetIds()
	var profiles map[ProfileID]Profile
	if len(ids) == 0 {
		profiles, err = app.connmgr.Profiles().List(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to list connections: %v", err)
		}
	} else {
		profiles = make(map[ProfileID]Profile)
		for _, id := range ids {
			profile, err := app.connmgr.Profiles().Get(ctx, ProfileID(id))
			if err != nil {
				if errors.IsNotFound(err) {
					continue
				}
				return nil, status.Errorf(codes.Internal, "failed to get connection: %v", err)
			}
			profiles[ProfileID(id)] = profile
		}
	}
	resp := &v1.ListConnectionsResponse{
		Connections: make(map[string]*v1.GetConnectionResponse),
	}
	for id, profile := range profiles {
		connStatus := app.connmgr.GetStatus(id.String())
		resp.Connections[id.String()] = &v1.GetConnectionResponse{
			Parameters: profile.ConnectionParameters,
			Status:     connStatus,
			Node: func() *v1.MeshNode {
				if connStatus == v1.DaemonConnStatus_CONNECTED {
					meshNode, err := app.connmgr.GetMeshNode(ctx, id.String())
					if err != nil {
						app.log.Error("Error getting mesh node", "id", id, "error", err.Error())
						return nil
					}
					return meshNode.MeshNode
				}
				return nil
			}(),
		}
	}
	return resp, nil
}

func (app *AppDaemon) Status(ctx context.Context, _ *v1.StatusRequest) (*v1.DaemonStatus, error) {
	connIDs, err := app.connmgr.Profiles().ListProfileIDs(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list connections: %v", err)
	}
	return &v1.DaemonStatus{
		NodeID:      app.connmgr.NodeID(),
		PublicKey:   app.connmgr.PublicKey(),
		Description: fmt.Sprintf("Webmesh App Daemon (%s)", runtime.Version()),
		Version:     app.version.Version,
		GitCommit:   app.version.GitCommit,
		BuildDate:   app.version.BuildDate,
		Uptime:      time.Since(app.started).String(),
		StartedAt:   timestamppb.New(app.started),
		Connections: func() map[string]v1.DaemonConnStatus {
			out := make(map[string]v1.DaemonConnStatus)
			for _, id := range connIDs {
				out[id.String()] = app.connmgr.GetStatus(id.String())
			}
			return out
		}(),
	}, nil
}

func newInvalidError(err error) error {
	return status.Errorf(codes.InvalidArgument, err.Error())
}
