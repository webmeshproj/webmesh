/*
Copyright 2023.

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
	rbacdb "github.com/webmeshproj/node/pkg/meshdb/rbac"
	"github.com/webmeshproj/node/pkg/services/rbac"
)

// Server is the webmesh Admin service.
type Server struct {
	v1.UnimplementedAdminServer

	store      meshdb.Store
	rbac       rbacdb.RBAC
	rbacEval   rbac.Evaluator
	networking networking.Networking
}

// New creates a new admin server.
func New(store meshdb.Store) *Server {
	return &Server{
		store:      store,
		rbac:       rbacdb.New(store),
		rbacEval:   rbac.NewStoreEvaluator(store),
		networking: networking.New(store),
	}
}
