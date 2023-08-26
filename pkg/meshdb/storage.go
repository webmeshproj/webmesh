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

// Package meshdb contains the schemas, generated code, and interfaces for
// interacting with the mesh database.
package meshdb

import (
	"context"
	"strings"

	"google.golang.org/grpc"

	"github.com/webmeshproj/webmesh/pkg/net"
	"github.com/webmeshproj/webmesh/pkg/plugins"
	"github.com/webmeshproj/webmesh/pkg/raft"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// Store is the interface for interacting with the mesh database and network.
// It is a reduced version of the mesh.Mesh interface. This interface should
// eventually go away.
type Store interface {
	// ID returns the ID of the node.
	ID() string
	// Domain returns the domain of the mesh network.
	Domain() string
	// Leader returns the current Raft leader.
	Leader() (string, error)
	// Storage returns a storage interface for use by the application.
	Storage() storage.MeshStorage
	// Raft returns the underlying Raft database.
	Raft() raft.Raft
	// Plugins returns the plugins for the current node.
	Plugins() plugins.Manager
	// Network returns the Network manager.
	Network() net.Manager
	// Dial opens a new gRPC connection to the given node.
	Dial(ctx context.Context, nodeID string) (*grpc.ClientConn, error)
	// DialLeader opens a new gRPC connection to the current Raft leader.
	DialLeader(ctx context.Context) (*grpc.ClientConn, error)
}

var reservedPrefixes = []string{
	"/registry/",
}

// IsReservedPrefix returns true if the given key is reserved.
func IsReservedPrefix(key string) bool {
	for _, prefix := range reservedPrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}
