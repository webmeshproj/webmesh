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
	"encoding/base64"
	"fmt"
	"log/slog"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/bufbuild/protovalidate-go"
	v1 "github.com/webmeshproj/api/go/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/webmesh/pkg/config"
	"github.com/webmeshproj/webmesh/pkg/context"
	"github.com/webmeshproj/webmesh/pkg/crypto"
	"github.com/webmeshproj/webmesh/pkg/embed"
	"github.com/webmeshproj/webmesh/pkg/meshnet/system/firewall"
	"github.com/webmeshproj/webmesh/pkg/storage"
	"github.com/webmeshproj/webmesh/pkg/storage/storageutil"
	"github.com/webmeshproj/webmesh/pkg/storage/types"
)

// AppDaemon is the app daemon RPC server.
type AppDaemon struct {
	v1.UnimplementedAppDaemonServer
	conns     map[string]embed.Node
	conf      Config
	nodeID    types.NodeID
	key       crypto.PrivateKey
	validator *protovalidate.Validator
	log       *slog.Logger
	mu        sync.RWMutex
}

var (
	// ErrNotConnected is returned when the node is not connected to the mesh.
	ErrNotConnected = status.Errorf(codes.FailedPrecondition, "not connected to the specified network")
	// ErrAlreadyConnected is returned when the node is already connected to the mesh.
	ErrAlreadyConnected = status.Errorf(codes.FailedPrecondition, "already connected to the specified network")
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
	var nodeID types.NodeID
	if conf.NodeID != "" {
		nodeID = types.NodeID(conf.NodeID)
	} else {
		nodeID = types.NodeID(key.ID())
	}
	return &AppDaemon{
		conns:     make(map[string]embed.Node),
		conf:      conf,
		nodeID:    nodeID,
		key:       key,
		validator: v,
		log:       conf.NewLogger().With("appdaemon", "server"),
	}, nil
}

func (app *AppDaemon) Connect(ctx context.Context, req *v1.ConnectRequest) (*v1.ConnectResponse, error) {
	err := app.validator.Validate(req)
	if err != nil {
		return nil, newInvalidError(err)
	}
	connID := req.GetId()
	app.mu.RLock()
	_, ok := app.conns[connID]
	if ok {
		app.mu.RUnlock()
		return nil, ErrAlreadyConnected
	}
	if connID == "" {
		var err error
		connID, err = crypto.NewRandomID()
		if err != nil {
			app.mu.RUnlock()
			return nil, status.Errorf(codes.Internal, "failed to generate connection ID: %v", err)
		}
		app.log.Info("Generated new connection ID", "id", connID)
		// Double check that the ID is unique.
		_, ok := app.conns[connID]
		if ok {
			app.mu.RUnlock()
			return nil, status.Errorf(codes.Internal, "connection ID collision")
		}
	}
	app.mu.RUnlock()
	app.log.Info("Creating new node with ID", "id", connID)
	cfg := app.buildConnConfig(ctx, req, connID)
	app.log.Debug("Node configuration", "config", cfg, "id", connID)
	node, err := embed.NewNode(ctx, embed.Options{
		Config: cfg,
		Key:    app.key,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create node: %v", err)
	}
	app.mu.Lock()
	app.conns[connID] = node
	app.mu.Unlock()
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
	app.mu.Lock()
	defer app.mu.Unlock()
	conn, ok := app.conns[req.GetId()]
	if !ok {
		return nil, ErrNotConnected
	}
	app.log.Info("Stopping node", "id", req.GetId())
	delete(app.conns, req.GetId())
	err = conn.Stop(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to stop node: %v", err)
	}
	return &v1.DisconnectResponse{}, nil
}

func (app *AppDaemon) Metrics(ctx context.Context, req *v1.MetricsRequest) (*v1.MetricsResponse, error) {
	err := app.validator.Validate(req)
	if err != nil {
		return nil, newInvalidError(err)
	}
	app.mu.RLock()
	defer app.mu.RUnlock()
	if len(req.GetIds()) > 0 {
		for _, id := range req.GetIds() {
			_, ok := app.conns[id]
			if !ok {
				return nil, ErrNotConnected
			}
		}
	}
	ids := req.GetIds()
	if len(ids) == 0 {
		ids = make([]string, 0, len(app.conns))
		for id := range app.conns {
			ids = append(ids, id)
		}
	}
	app.log.Info("Getting metrics for connections", "ids", ids)
	res := &v1.MetricsResponse{
		Interfaces: make(map[string]*v1.InterfaceMetrics),
	}
	for _, i := range ids {
		id := i
		conn := app.conns[id]
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
	app.mu.RLock()
	defer app.mu.RUnlock()
	c, ok := app.conns[req.GetId()]
	if !ok {
		app.log.Info("Status requested for unknown connection", "id", req.GetId())
		return &v1.StatusResponse{
			ConnectionStatus: v1.StatusResponse_DISCONNECTED,
		}, nil
	}
	app.log.Info("Retrieving status for connection", "id", req.GetId())
	return &v1.StatusResponse{
		ConnectionStatus: func() v1.StatusResponse_ConnectionStatus {
			if c.MeshNode().Started() {
				return v1.StatusResponse_CONNECTED
			}
			return v1.StatusResponse_CONNECTING
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
	}, nil
}

func (app *AppDaemon) Query(ctx context.Context, req *v1.AppQueryRequest) (*v1.QueryResponse, error) {
	err := app.validator.Validate(req)
	if err != nil {
		return nil, newInvalidError(err)
	}
	app.mu.RLock()
	defer app.mu.RUnlock()
	conn, ok := app.conns[req.GetId()]
	if !ok {
		return nil, ErrNotConnected
	}
	app.log.Info("Querying storage for connection", "id", req.GetId())
	return storageutil.ServeStorageQuery(ctx, conn.MeshNode().Storage(), req.GetQuery())
}

func (app *AppDaemon) Close() error {
	app.mu.Lock()
	defer app.mu.Unlock()
	for id, conn := range app.conns {
		app.log.Info("Stopping node", "id", id)
		err := conn.Stop(context.WithLogger(context.Background(), app.log))
		if err != nil {
			app.log.Error("Error stopping node", "err", err)
		}
	}
	app.conns = nil
	return nil
}

func (app *AppDaemon) buildConnConfig(ctx context.Context, req *v1.ConnectRequest, connID string) *config.Config {
	conf := config.NewDefaultConfig(app.nodeID.String())
	conf.Storage.InMemory = true
	if app.conf.Persistence.Path != "" {
		conf.Storage.InMemory = false
		conf.Storage.Path = filepath.Join(app.conf.Persistence.Path, connID)
	}
	conf.WireGuard.ListenPort = 0
	if runtime.GOOS != "darwin" {
		// Set a unique interface name on non-darwin systems.
		conf.WireGuard.InterfaceName = connID + "0"
	}
	conf.Global.LogLevel = app.conf.LogLevel
	conf.Global.LogFormat = app.conf.LogFormat
	conf.Storage.LogLevel = app.conf.LogLevel
	conf.Storage.LogFormat = app.conf.LogFormat
	conf.Services.API.Disabled = !req.GetServices().GetEnabled()
	conf.Bootstrap.Enabled = req.GetBootstrap().GetEnabled()
	if conf.Bootstrap.Enabled {
		conf.Bootstrap.Admin = app.nodeID.String()
		conf.Bootstrap.DisableRBAC = !req.GetBootstrap().GetRbacEnabled()
		conf.Bootstrap.IPv4Network = storage.DefaultIPv4Network
		conf.Bootstrap.MeshDomain = storage.DefaultMeshDomain
		if req.GetBootstrap().GetIpv4Network() != "" {
			conf.Bootstrap.IPv4Network = req.GetBootstrap().GetIpv4Network()
		}
		if req.GetBootstrap().GetDomain() != "" {
			conf.Bootstrap.MeshDomain = req.GetBootstrap().GetDomain()
		}
		switch req.GetBootstrap().GetDefaultNetworkACL() {
		case v1.MeshConnBootstrap_ACCEPT:
			conf.Bootstrap.DefaultNetworkPolicy = string(firewall.PolicyAccept)
		case v1.MeshConnBootstrap_DROP:
			conf.Bootstrap.DefaultNetworkPolicy = string(firewall.PolicyDrop)
		default:
			conf.Bootstrap.DefaultNetworkPolicy = string(firewall.PolicyAccept)
		}
	}
	conf.TLS.Insecure = !req.GetTls().GetEnabled()
	if !conf.TLS.Insecure {
		if len(req.GetTls().GetCaCertData()) != 0 {
			conf.TLS.CAData = base64.StdEncoding.EncodeToString(req.GetTls().GetCaCertData())
		}
		conf.TLS.VerifyChainOnly = req.GetTls().GetVerifyChainOnly()
		conf.TLS.InsecureSkipVerify = req.GetTls().GetSkipVerify()
	}
	switch req.GetAddrType() {
	case v1.ConnectRequest_ADDR:
		conf.Mesh.JoinAddresses = req.GetAddrs()
	case v1.ConnectRequest_RENDEZVOUS:
		conf.Discovery.Discover = true
		conf.Discovery.Rendezvous = req.GetAddrs()[0]
	case v1.ConnectRequest_MULTIADDR:
		conf.Mesh.JoinMultiaddrs = req.GetAddrs()
	}
	switch req.GetAuthMethod() {
	case v1.ConnectRequest_NO_AUTH:
	case v1.ConnectRequest_BASIC:
		conf.Auth.Basic.Username = string(req.GetAuthCredentials()[v1.ConnectRequest_BASIC_USERNAME.String()])
		conf.Auth.Basic.Password = string(req.GetAuthCredentials()[v1.ConnectRequest_BASIC_PASSWORD.String()])
	case v1.ConnectRequest_LDAP:
		conf.Auth.LDAP.Username = string(req.GetAuthCredentials()[v1.ConnectRequest_LDAP_USERNAME.String()])
		conf.Auth.LDAP.Password = string(req.GetAuthCredentials()[v1.ConnectRequest_LDAP_PASSWORD.String()])
	case v1.ConnectRequest_MTLS:
		conf.Auth.MTLS.CertData = base64.StdEncoding.EncodeToString(req.GetTls().GetCertData())
		conf.Auth.MTLS.KeyData = base64.StdEncoding.EncodeToString(req.GetTls().GetKeyData())
	case v1.ConnectRequest_ID:
		conf.Auth.IDAuth.Enabled = true
	}
	return conf
}

func newInvalidError(err error) error {
	return status.Errorf(codes.InvalidArgument, err.Error())
}
