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

// Package node contains the webmesh node service.
package node

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/webmeshproj/node/pkg/meshdb/networking"
	"github.com/webmeshproj/node/pkg/meshdb/peers"
	rbacdb "github.com/webmeshproj/node/pkg/meshdb/rbac"
	"github.com/webmeshproj/node/pkg/meshdb/state"
	"github.com/webmeshproj/node/pkg/services/rbac"
	"github.com/webmeshproj/node/pkg/store"
)

// Server is the webmesh node service.
type Server struct {
	v1.UnimplementedNodeServer

	store      store.Store
	peers      peers.Peers
	meshstate  state.State
	rbac       rbacdb.RBAC
	rbacEval   rbac.Evaluator
	networking networking.Networking

	ipv4Prefix netip.Prefix
	ipv6Prefix netip.Prefix
	features   []v1.Feature
	startedAt  time.Time
	log        *slog.Logger
	proxyCreds []grpc.DialOption
	// insecure flags that no authentication plugins are enabled.
	insecure bool
	// lock taken during the join process to prevent concurrent joins.
	joinmu sync.Mutex
}

// NewServer returns a new Server. Features are used for returning what features are enabled.
// It is the callers responsibility to ensure those servers are registered on the node.
// Insecure is used to disable authorization.
func NewServer(store store.Store, proxyCreds []grpc.DialOption, features []v1.Feature, insecure bool) *Server {
	var rbaceval rbac.Evaluator
	if insecure {
		rbaceval = rbac.NewNoopEvaluator()
	} else {
		rbaceval = rbac.NewStoreEvaluator(store)
	}
	return &Server{
		store:      store,
		peers:      peers.New(store.DB()),
		meshstate:  state.New(store.DB()),
		rbac:       rbacdb.New(store.DB()),
		rbacEval:   rbaceval,
		networking: networking.New(store.DB()),
		features:   features,
		startedAt:  time.Now(),
		proxyCreds: proxyCreds,
		insecure:   insecure,
		log:        slog.Default().With("component", "node-server"),
	}
}

func (s *Server) newPrivateRemoteNodeConn(ctx context.Context, nodeID string) (*grpc.ClientConn, error) {
	addr, err := s.meshstate.GetNodePrivateRPCAddress(ctx, nodeID)
	if err != nil {
		if errors.Is(err, state.ErrNodeNotFound) {
			return nil, status.Errorf(codes.NotFound, "node %s not found", nodeID)
		}
		return nil, status.Errorf(codes.FailedPrecondition, "could not find rpc address for node %s: %s", nodeID, err.Error())
	}
	s.log.Info("dialing node", slog.String("node", nodeID), slog.String("addr", addr.String()))
	conn, err := s.newRemoteNodeConnForAddr(ctx, addr.String())
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "could not connect to node %s: %s", nodeID, err.Error())
	}
	return conn, nil
}

func (s *Server) newRemoteNodeConnForAddr(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	conn, err := grpc.DialContext(ctx, addr, s.proxyCreds...)
	if err != nil {
		return nil, fmt.Errorf("could not connect to node %s: %w", addr, err)
	}
	return conn, nil
}
