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

// Package admin provides the admin gRPC server.
package admin

import (
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/node/pkg/meshdb"
	"github.com/webmeshproj/node/pkg/meshdb/networking"
	"github.com/webmeshproj/node/pkg/meshdb/peers"
	rbacdb "github.com/webmeshproj/node/pkg/meshdb/rbac"
	"github.com/webmeshproj/node/pkg/services/rbac"
)

// Server is the webmesh Admin service.
type Server struct {
	v1.UnimplementedAdminServer

	store      meshdb.Store
	peers      peers.Peers
	rbac       rbacdb.RBAC
	rbacEval   rbac.Evaluator
	networking networking.Networking
}

// New creates a new admin server.
func New(store meshdb.Store, insecure bool) *Server {
	rbacEval := rbac.NewStoreEvaluator(store)
	if insecure {
		rbacEval = rbac.NewNoopEvaluator()
	}
	return &Server{
		store:      store,
		peers:      peers.New(store.Storage()),
		rbac:       rbacdb.New(store.Storage()),
		rbacEval:   rbacEval,
		networking: networking.New(store.Storage()),
	}
}
