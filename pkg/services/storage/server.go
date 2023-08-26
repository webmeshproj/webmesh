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

// Package storage provides the storage server.
package storage

import (
	"log/slog"

	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/meshdb"
	"github.com/webmeshproj/webmesh/pkg/services/rbac"
)

// Server is the webmesh storage server.
type Server struct {
	v1.UnimplementedStorageServer

	store meshdb.Store
	rbac  rbac.Evaluator
	log   *slog.Logger
}

// NewServer returns a new storage Server.
func NewServer(store meshdb.Store, insecure bool) *Server {
	var rbaceval rbac.Evaluator
	if insecure {
		rbaceval = rbac.NewNoopEvaluator()
	} else {
		rbaceval = rbac.NewStoreEvaluator(store)
	}
	return &Server{
		store: store,
		rbac:  rbaceval,
		log:   slog.Default().With("component", "storage-server"),
	}
}
