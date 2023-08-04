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
	"net/netip"
	"sync"
	"time"

	v1 "github.com/webmeshproj/api/v1"
	"golang.org/x/exp/slog"

	"github.com/webmeshproj/webmesh/pkg/mesh"
	"github.com/webmeshproj/webmesh/pkg/meshdb/networking"
	"github.com/webmeshproj/webmesh/pkg/meshdb/peers"
	rbacdb "github.com/webmeshproj/webmesh/pkg/meshdb/rbac"
	"github.com/webmeshproj/webmesh/pkg/meshdb/state"
	"github.com/webmeshproj/webmesh/pkg/services/rbac"
)

// Server is the webmesh node service.
type Server struct {
	v1.UnimplementedNodeServer

	store      mesh.Mesh
	peers      peers.Peers
	meshstate  state.State
	rbac       rbacdb.RBAC
	rbacEval   rbac.Evaluator
	networking networking.Networking

	ipv4Prefix netip.Prefix
	ipv6Prefix netip.Prefix
	meshDomain string
	features   []v1.Feature
	startedAt  time.Time
	log        *slog.Logger
	// insecure flags that no authentication plugins are enabled.
	insecure bool
	// lock taken during the join/update process to prevent concurrent node changes.
	mu sync.Mutex
}

// NewServer returns a new Server. Features are used for returning what features are enabled.
// It is the callers responsibility to ensure those servers are registered on the node.
// Insecure is used to disable authorization.
func NewServer(store mesh.Mesh, features []v1.Feature, insecure bool) *Server {
	var rbaceval rbac.Evaluator
	if insecure {
		rbaceval = rbac.NewNoopEvaluator()
	} else {
		rbaceval = rbac.NewStoreEvaluator(store)
	}
	return &Server{
		store:      store,
		peers:      peers.New(store.Storage()),
		meshstate:  state.New(store.Storage()),
		rbac:       rbacdb.New(store.Storage()),
		rbacEval:   rbaceval,
		networking: networking.New(store.Storage()),
		features:   features,
		startedAt:  time.Now(),
		insecure:   insecure,
		log:        slog.Default().With("component", "node-server"),
	}
}
