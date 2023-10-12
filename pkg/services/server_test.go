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

// Package services contains the gRPC server for inter-node communication.
package services

import (
	"testing"

	"github.com/webmeshproj/webmesh/pkg/services/meshdns"
)

func TestGetServerByType(t *testing.T) {
	servers := MeshServers{
		&meshdns.Server{},
	}
	srv, ok := servers.GetByType(&meshdns.Server{})
	if !ok {
		t.Fatal("expected to find server")
	}
	if srv == nil {
		t.Fatal("expected server to not be nil")
	}
	if _, ok := srv.(*meshdns.Server); !ok {
		t.Fatal("expected server to be of type *meshdns.Server")
	}

	// Try the generic one too.
	dnsSrv, ok := GetByType(servers, &meshdns.Server{})
	if !ok {
		t.Fatal("expected to find server")
	}
	if dnsSrv == nil {
		t.Fatal("expected server to not be nil")
	}
}
