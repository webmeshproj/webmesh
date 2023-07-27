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
	"github.com/hashicorp/raft"
	_ "github.com/mattn/go-sqlite3"

	"github.com/webmeshproj/webmesh/pkg/net/wireguard"
	"github.com/webmeshproj/webmesh/pkg/plugins"
	"github.com/webmeshproj/webmesh/pkg/storage"
)

// Store is the interface for interacting with the mesh database. It is a reduced
// version of the store.Store interface.
type Store interface {
	// ID returns the ID of the node.
	ID() string
	// Storage returns a storage interface for use by the application.
	Storage() storage.Storage
	// Raft returns the underlying Raft database.
	Raft() *raft.Raft
	// Leader returns the current Raft leader.
	Leader() (raft.ServerID, error)
	// IsLeader returns whether the current node is the Raft leader.
	IsLeader() bool
	// Plugins returns the plugins for the current node.
	Plugins() plugins.Manager
	// WireGuard returns the Wireguard interface. Note that the returned value
	// may be nil if the store is not open.
	WireGuard() wireguard.Interface
}
