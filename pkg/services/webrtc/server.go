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

// Package webrtc contains the webmesh WebRTC service.
package webrtc

import (
	v1 "github.com/webmeshproj/api/v1"

	"github.com/webmeshproj/webmesh/pkg/meshdb"
	"github.com/webmeshproj/webmesh/pkg/meshdb/state"
	"github.com/webmeshproj/webmesh/pkg/services/rbac"
)

// Server is the webmesh WebRTC service.
type Server struct {
	v1.UnimplementedWebRTCServer

	store       meshdb.Store
	meshstate   state.State
	rbacEval    rbac.Evaluator
	stunServers []string
}

// NewServer returns a new Server.
func NewServer(store meshdb.Store, stunServers []string, insecure bool) *Server {
	var rbaceval rbac.Evaluator
	if insecure {
		rbaceval = rbac.NewNoopEvaluator()
	} else {
		rbaceval = rbac.NewStoreEvaluator(store)
	}
	return &Server{
		store:       store,
		meshstate:   state.New(store.Storage()),
		rbacEval:    rbaceval,
		stunServers: stunServers,
	}
}
